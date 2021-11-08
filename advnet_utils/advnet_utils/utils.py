from __future__ import print_function
import subprocess
import math
import pandas as pd
import sys
import os
import json
import pathlib
import re
import time
from p4utils.mininetlib.log import debug, info, output, warning, error


def load_conf(conf_file):
    with open(conf_file, 'r') as f:
        config = json.load(f)
    return config


def log_error(*items):
    print(*items, file=sys.stderr)


def run_command(command):
    print(command)
    return os.WEXITSTATUS(os.system(command))

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
        conversions = {'Bps': 1, 'Kbps': 1e3, 'Mbps': 1e6, 'Gbps': 1e9}

        digits_list = "0123456789."
        digit = float("".join([x for x in size if x in digits_list]))
        magnitude = "".join([x for x in size if x not in digits_list])
        magnitude = magnitude.upper()
        magnitude = conversions[magnitude]
        return int(magnitude*digit)
    except:
        print("Conversion Fail")
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


def tcp_perf(sender_csv, receiver_csv):
    """Assess TCP flow performance.

    Args:
        sender_csv (str): Name of the sender .csv file
        receiver_csv (str): Name of the receiver .csv file

    Returns:
        tuple: Flow Completion Rate, average delay and Flow Completion Time
    """
    # Open sender and receive .csv files
    sender_s = pd.read_csv(sender_csv)['t_timestamp']
    receiver_s = pd.read_csv(receiver_csv)['r_timestamp']

    # Get tot_bytes
    tot_bytes = sender_s.pop(0)
    # Get recv_bytes
    recv_bytes = receiver_s.pop(len(receiver_s) - 1)

    # Reset index of sender_s
    sender_s.reset_index(drop=True, inplace=True)

    # Get indexes of sender_s and receiver_s
    send_index = sender_s.index
    recv_index = receiver_s.index

    # Intestection of indexes to make sure we are considering only delivered data
    common_index = send_index.intersection(recv_index)

    # Compute average delay
    avg_delay = (receiver_s[common_index] - sender_s[common_index]).mean()

    # Compute packet reception ratio
    fcr = recv_bytes / tot_bytes

    # Compute flow completion time
    if fcr == 1:
        fct = sender_s.iloc[-1] - sender_s.iloc[1]
    else:
        fct = None

    return fcr, avg_delay, fct


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
