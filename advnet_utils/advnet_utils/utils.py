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
from p4utils.mininetlib.log import info


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


## Utils
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

# Traffic Generation Utils.
# =========================


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


def print_output_performances(outputdir):
    """Prints and save udp and tcp flows perfromances"""

    # Storing array
    results = []
    header = [
        'src', 'dst', 'sport', 'dport', 'protocol',
        'prr', 'delay', 'rtt', 'fct'
    ]
    results_file = 'results.csv'


    print("Experiment performances: {}".format(outputdir))
    print("=====================================\n")
    output_files = glob.glob(outputdir + "/*.csv")
    udp_flows = [x for x in output_files if "udp" in x]
    tcp_flows = [x for x in output_files if "tcp" in x]

    # process udp flows
    print("UDP Flows:")
    print("==========")
    udp_senders = [x for x in udp_flows if "send" in x]
    for udp_sender in udp_senders:
        # get flow info
        _str = udp_sender.split("/")[-1]
        _str = _str.replace("send-", "")
        _str = _str.replace("_udp.csv", "")
        #import ipdb; ipdb.set_trace()
        node1, h1, node2, h2, sport, dport = _str.split("_")
        udp_receiver = udp_sender.replace("send", "recv")
        performance = udp_perf(udp_sender, udp_receiver)
        print("{}:{}->{}:{}: {}".format(node1+"_"+h1, sport, node2+"_"+h2, dport, performance))
        results.append([
            node1+"_"+h1,
            node2+"_"+h2,
            sport,
            dport,
            'udp',
            performance[0], # PRR
            performance[1], # delay
            '',             # RTT/tcp delay (whatever that means)
            ''              # FCT
        ])
    print("\n")
    # process tcp flows
    print("TCP Flows:")
    print("==========")
    tcp_senders = [x for x in tcp_flows if "send" in x]
    for tcp_sender in tcp_senders:
        _str = tcp_sender.split("/")[-1]
        _str = _str.replace("send-", "")
        _str = _str.replace("_tcp.csv", "")
        node1, h1, node2, h2, sport, dport = _str.split("_")
        tcp_receiver = tcp_sender.replace("send", "recv")
        performance = tcp_perf(tcp_sender, tcp_receiver)
        print("{}:{}->{}:{}: {}".format(node1+"_"+h1, sport, node2+"_"+h2, dport, performance))
        results.append([
            node1+"_"+h1,
            node2+"_"+h2,
            sport,
            dport,
            'tcp',
            performance[0], # PRR
            '',             # delay
            performance[1], # RTT/tcp delay (whatever that means)
            performance[2]  # FCT
        ])

    # save all results
    with open(pathlib.Path(outputdir,results_file), 'w', encoding='UTF8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(results)

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
def wait_experiment(start_time, experiment_length, receivers_wait_offset=10):
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
