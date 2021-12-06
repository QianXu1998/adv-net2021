import subprocess
import math
import pandas as pd
import sys
import os
import json
import pathlib
import re
import time
import glob
import csv
import ipdb
from p4utils.mininetlib.log import info
from advnet_utils.pcap_parser import pcap_to_flows_sequences

def load_conf(conf_file):
    with open(conf_file, 'r') as f:
        config = json.load(f)
    return config


def log_error(*items):
    print(*items, file=sys.stderr)


def run_command(command):
    print(command)
    return os.WEXITSTATUS(os.system(command))

def get_user():
    """Try to find the user who called sudo/pkexec."""
    user = subprocess.check_output("echo ${SUDO_USER:-${USER}}", shell=True)
    return user.strip().decode("utf-8") 

# Rate Conversions
#=================

def _parse_rate(rate):
    """Parse a given rate in B/s.

    Args:
        rate (str or float): Rate.

    Note:
        String input size can be given with the following magnitudes: 
        **bps**, **Kbps**, **Mbps** and **Gbps**. If the input rate is a 
        :py:class:`int`, then it is assumed as bps.

    Returns:
        float: rate in B/s.
    """
    conversions = {'bps': 1, 'Kbps': 1e3, 'Mbps': 1e6, 'Gbps': 1e9}

    if isinstance(rate, int):
        return rate/8
    elif isinstance(rate, str):
        regex = r'^(?P<rate>\d+(?:\.\d+)?)\s*(?P<unit>\w+)$'
        match = re.search(regex, rate)
        if match is not None:
            rate = match.group('rate')
            unit = match.group('unit')
            if unit in conversions.keys():
                return float(rate)*conversions[unit]/8
            else:
                Exception('unit "{}" not recognized in "{}"!'.format(unit, rate))
        else:
            raise Exception('cannot parse "{}"!'.format(rate))
    else:
        raise Exception('conversion from {} not supported!'.format(type(rate)))


def _parse_size(size):
    """Parse a given size in Bytes.

    Args:
        size (str or int): size.

    Note:
        String input size can be given with the following magnitudes: 
        **B**, **KB**, **MB** and **GB**. If the input rate is a 
        :py:class:`int`, then it is assumed as bps.

    Returns:
        int: size in Bytes.
    """

    conversions = {'B': 1, 'KB': 1e3, 'MB': 1e6, 'GB': 1e9}

    if isinstance(size, int):
        return size
    elif isinstance(size, str):
        regex = r'^(?P<size>\d+(?:\.\d+)?)\s*(?P<unit>\w+)$'
        match = re.search(regex, size)
        if match is not None:
            size = match.group('size')
            unit = match.group('unit')
            if unit in conversions.keys():
                return math.ceil(float(size)*conversions[unit])
            else:
                Exception('unit "{}" not recognized in "{}"!'.format(unit, size))
        else:
            raise Exception('cannot parse "{}"!'.format(size))
    else:
        raise Exception('conversion from {} not supported!'.format(type(size)))


def setSizeToInt(size):
    """" Converts the sizes string notation to the corresponding integer
    (in bytes).  Input size can be given with the following
    magnitudes: B, K, M and G.
    """
    if isinstance(size, int):
        return size
    elif isinstance(size, float):
        return int(size)
    try:
        conversions = {'B': 1, 'K': 1e3, 'M': 1e6, 'G': 1e9}
        conversions.update({'B': 1, 'KB': 1e3, 'MB': 1e6, 'GB': 1e9})

        digits_list = "0123456789."
        digit = float("".join([x for x in size if x in digits_list]))
        magnitude = "".join([x for x in size if x not in digits_list])
        magnitude = magnitude.upper()
        magnitude = conversions[magnitude]
        return int(magnitude*digit)
    except:
        print("Conversion Fail")
        return 0


def setRateToInt(size):
    """" Converts the sizes string notation to the corresponding integer
    (in bytes).  Input size can be given with the following
    magnitudes: Bbps, Kbps, Mbps and Gbps.
    """
    try:
        conversions = {'bps': 1, 'kbps': 1e3, 'mbps': 1e6, 'gbps': 1e9}

        digits_list = "0123456789."
        digit = float("".join([x for x in size if x in digits_list]))
        magnitude = "".join([x for x in size if x not in digits_list])
        magnitude = magnitude.lower()
        magnitude = conversions[magnitude]
        return int(magnitude*digit)
    except:
        print("Conversion Fail")
        import traceback
        traceback.print_exc()
        return 0

# Flow performance utils
########################

def udp_perf(sender_csv, receiver_csv):
    """Assess UDP flow performance.

    Args:
        sender_csv (str): Name of the sender .csv file
        receiver_csv (str): Name of the receiver .csv file

    Returns:
        tuple: PRR (Packet Reception Ratio) and average delay
    """
    # Open sender and receive .csv files
    sender_df = pd.read_csv(sender_csv)
    receiver_df = pd.read_csv(receiver_csv)

    # Remove duplicated sequence numbers
    receiver_df.drop_duplicates(subset='seq_num', keep='first', inplace=True)

    # Intersection between sent and received packets with timestamps
    delivered_df = pd.merge(sender_df, receiver_df, how='inner', on='seq_num')

    # Compute average delay (only for delivered packets)
    avg_delay = (delivered_df['r_timestamp'] -
                 delivered_df['t_timestamp']).mean()

    # Compute packet reception ratio
    prr = len(delivered_df) / len(sender_df)
    return prr, avg_delay

def tcp_perf(sender_csv, *args):
    """Assess TCP flow performance.

    Args:
        sender_csv (str): Name of the sender .csv file

    Returns:
        tuple: Flow Completion Rate, average delay and Flow Completion Time
    """
    # Open sender and receive .csv files
    sender_s = pd.read_csv(sender_csv)['rtt']

    # Get tot_bytes
    tot_bytes = sender_s.pop(0)

    fcr, avg_rtt, fct = (0.0, None, None)
    if not sender_s.empty:
        # Get unsent_bytes
        unsent_bytes = sender_s.pop(len(sender_s))
        # Get elapsed_time
        elapsed_time = sender_s.pop(len(sender_s))

        # Reset index of sender_s
        sender_s.reset_index(drop=True, inplace=True)

        # Compute average delay from average RTT
        avg_rtt = sender_s.mean() / (10**6)

        # Compute flow completion ratio
        fcr = 1 - (unsent_bytes / tot_bytes)

        # Compute flow completion time
        if fcr == 1:
            fct = elapsed_time
        else:
            fct = None

    return fcr, avg_rtt, fct

def get_experiment_performances(outputdir, results_file='results.csv'):
    """Computes all the experiment performances and saves into file"""

    # Storing array
    results = []
    header = [
        'src', 'dst', 'sport', 'dport', 'protocol',
        'prr', 'delay', 'rtt', 'fct', 'wpr'
    ]

    # load waypoint performances (asume only udp flows)
    wp_performances = waypoint_perf(outputdir)

    output_files = glob.glob(outputdir + "/*.csv")
    udp_flows = [x for x in output_files if "udp" in x]
    tcp_flows = [x for x in output_files if "tcp" in x]

    # process udp flows
    udp_senders = [x for x in udp_flows if "send" in x]
    for udp_sender in udp_senders:
        # get flow info
        _str = udp_sender.split("/")[-1]
        _str = _str.replace("send-", "")
        _str = _str.replace("_udp.csv", "")
        node1, h1, node2, h2, sport, dport = _str.split("_")
        udp_receiver = udp_sender.replace("send", "recv")
        performance = udp_perf(udp_sender, udp_receiver)

        flow_key = (
            node1+"_"+h1,
            node2+"_"+h2,
            sport,
            dport,
            'udp',
        )
        
        wpr = wp_performances.get(flow_key, '')

        delay = performance[1]
        delay = delay if not (math.isnan(delay)) else ''

        results.append([
            node1+"_"+h1,
            node2+"_"+h2,
            sport,
            dport,
            'udp',
            performance[0], # PRR
            delay, # delay
            '',             # RTT/tcp delay (whatever that means)
            '',             # FCT
            wpr             # WPR Waypoint performance
        ])
    # process tcp flows
    tcp_senders = [x for x in tcp_flows if "send" in x]
    for tcp_sender in tcp_senders:
        _str = tcp_sender.split("/")[-1]
        _str = _str.replace("send-", "")
        _str = _str.replace("_tcp.csv", "")
        node1, h1, node2, h2, sport, dport = _str.split("_")
        tcp_receiver = tcp_sender.replace("send", "recv")
        performance = tcp_perf(tcp_sender, tcp_receiver)
        results.append([
            node1+"_"+h1,
            node2+"_"+h2,
            sport,
            dport,
            'tcp',
            performance[0], # PRR
            '',             # delay
            performance[1], # RTT/tcp delay (whatever that means)
            performance[2], # FCT
            ''              # WPR Waypoint performance
        ])

    if results_file:
        # save all results
        with open(pathlib.Path(outputdir,results_file), 'w', encoding='UTF8', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(header)
            writer.writerows(results)    
    return results

def print_experiment_performances(outputdir):
    """Prints and save udp and tcp flows performances"""

    results = get_experiment_performances(outputdir)
    
    welcome = "Experiment performance: {}".format(outputdir)
    print()
    print("-" * len(welcome))
    print(welcome)
    print("-" * len(welcome))
    print()

    base_str = "{:<35}{:^16}{:^16}{:^16}"
    data_base_str = "{:<35}{:^16}{:^16}{:^16}"

    # udp table
    dash = '-' * len(base_str.format("","","",""))
    print(dash)
    print(base_str.format("UDP Flow", "Reception Rate", "Avg Delay", "Waypoint Rate"))
    print(dash)
    for flow in results:
        if flow[4] == "udp":
            _flow = "{:<8}{:<8}{:>6}{:>6}".format(*flow[:4])
            prr, delay, wpr = flow[5], flow[6], flow[9]
            if isinstance(prr, float):
                prr = round(prr, 6)
            else:
                prr = "-"
            if isinstance(delay, float):
                delay = round(delay, 4)                
            else:
                delay = "-"
            if isinstance(wpr, float):
                wpr = round(wpr, 6)                
            else:
                wpr = '-'
            print(data_base_str.format(_flow, prr, delay, wpr))

    print()

    # tcp table
    base_str = "{:<35}{:^16}{:^16}{:^16}"
    data_base_str = "{:<35}{:^16}{:^16}{:^16}"
    dash = '-' * len(base_str.format("","","",""))
    print(dash)
    print(base_str.format("TCP Flow", "Completion Rate", "Avg RTT", "FCT"))
    print(dash)
    for flow in results:
        if flow[4] == "tcp":
            _flow = "{:<8}{:<8}{:>6}{:>6}".format(*flow[:4])
            pcr, rtt, fct = flow[5], flow[7], flow[8]
            if isinstance(pcr, float):
                pcr = round(pcr, 6)
            else:
                pcr = "-"
            if isinstance(rtt, float):
                rtt = round(rtt, 4)                
            else:
                rtt = "-"
            if isinstance(fct, float):
                fct = round(fct, 6)                
            else:
                fct = '-'
            print(data_base_str.format(_flow, pcr, rtt, fct))

# Waypoint Performance Utils
############################

def waypoint_perf(outputdir):
    """Gets waypoint performances"""
    
    # get list of flows that needed to be waypointed
    waypoint_flows_file = outputdir + "/waypoint_flows.txt"
    with open(waypoint_flows_file, "r", newline='') as waypoint_file:
        reader = csv.DictReader(waypoint_file)
        waypoint_flows = [flow for flow in reader]

    # get targets
    targets = set([x["target"] for x in waypoint_flows])
    # Parse all pcap files for each target
    target_to_flow_sequences = {}
    for target in targets:
        target_to_flow_sequences[target] = {}
        pcaps = glob.glob("{}/{}*.pcap".format(outputdir, target))
        for pcap in pcaps:
            flow_to_sequences = {}
            try:
                flow_to_sequences = pcap_to_flows_sequences(pcap)
            except:
                pass
            # merge all sequences for the same flow and node
            for flow, sequences in flow_to_sequences.items():
                target_to_flow_sequences[target].setdefault(flow, set()).update(sequences)

    flow_wp_performances = {}
    # read receiver sequences
    for flow in waypoint_flows:
        receiver_file = "{}/recv-{}_{}_{}_{}_{}.csv".format(outputdir, 
                                                            flow["src"],
                                                            flow["dst"], 
                                                            flow["sport"], 
                                                            flow["dport"], 
                                                            flow["protocol"])
        try:
            receiver_df = pd.read_csv(receiver_file)
        except FileNotFoundError:
            return flow_wp_performances  # Nothing to return
        receiver_df.drop_duplicates(
            subset='seq_num', keep='first', inplace=True)

        flow_key = (
            flow["src_ip"], 
            flow["dst_ip"], 
            int(flow["sport"]), 
            int(flow["dport"]), 
            flow["protocol"]
        )
        # get both sequence sets
        target_seqs = target_to_flow_sequences[flow["target"]].get(flow_key, set())
        receiver_seqs = set(receiver_df["seq_num"].tolist())
        # received seqs that have been waypointed
        wp_seqs = receiver_seqs.intersection(target_seqs)
        if len(receiver_seqs) == 0:
            wp_rate = 0.0
        else:
            wp_rate = len(wp_seqs)/len(receiver_seqs)

        flow_key2 = (
            flow["src"], 
            flow["dst"], 
            flow["sport"], 
            flow["dport"], 
            flow["protocol"]
        )
        flow_wp_performances[flow_key2] = wp_rate
    return flow_wp_performances                                   
    
# Main Runner Utils
# =================

def load_constrains(constrains_file):
    """returns the project constrains"""
    return json.load(open(constrains_file, "r"))


def install_requirements(requirements_file):
    """Installs python requirements for the controller"""
    subprocess.call(
        "pip3 install -r {} 2>&1".format(requirements_file), shell=True)


def uninstall_requirements(requirements_file):
    """Uninstalls python requirements for the controller"""
    subprocess.call(
        "pip3 uninstall -y -r {} 2>&1".format(requirements_file), shell=True)


def install_non_optimized_switch(src_path="~/p4-tools/bmv2/"):
    """Installs the non optimized switch"""
    src_path = src_path.replace("~", str(pathlib.Path.home()))
    subprocess.call("sudo make install", cwd=src_path, shell=True)
    subprocess.call("sudo ldconfig", cwd=src_path, shell=True)


def install_optimized_switch(src_path="~/p4-tools/bmv2-opt/"):
    """Installs the optimized switch"""
    src_path = src_path.replace("~", str(pathlib.Path.home()))
    subprocess.call("sudo make install", cwd=src_path, shell=True)
    subprocess.call("sudo ldconfig", cwd=src_path, shell=True)


def clean_dir(src_path):
    """Clean directory"""
    src_path = src_path.replace("~", str(pathlib.Path.home()))
    if not os.path.exists(src_path):
        raise Exception("Path {} does not exist".format(src_path))
    subprocess.call("sudo p4run --clean-dir", shell=True, cwd=src_path)

# Experiment Utils
# ================
def wait_experiment(start_time, experiment_length, outputdir, receivers_wait_offset=10):
    """Basic function to wait for the experiments to be run"""
    info("Scheduling Tasks...\n")
    info("===================\n\n")
    time.sleep(max(start_time - time.time(), 0))
    info("Experiment Starts...\n")
    info("====================\n\n")
    time.sleep(experiment_length)
    info("Waiting to close receivers...\n")
    info("=============================\n\n")
    time.sleep(receivers_wait_offset)
    info("Experiment done...\n")
    info("==================\n\n")
