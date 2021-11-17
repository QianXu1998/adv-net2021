#!/usr/bin/env python
"""Adv-net 2021 project CLI"""
import os, sys
from advnet_utils.get_city_info import Delay
from advnet_utils.monitoring import monitor_network
from p4utils.utils.helper import load_topo
from advnet_utils.utils import install_requirements, load_conf, uninstall_requirements, install_non_optimized_switch, install_optimized_switch, clean_dir, print_output_performances
cur_dir = os.path.dirname(os.path.abspath(__file__)) + "/"

# CLI
# ==========
def experiment_performance(outdir):
    print_output_performances(outdir)

def monitor(topo_path):
    """Start monitoring"""
    monitor_network(load_topo(topo_path))

def help():
    _help = """
Usage: ./cli.py COMMAND [ARGS...]

Commands:
=========
help                           Shows the help menu.
clean [path]                   Cleans a working P4 directory.
monitor                        Print the bit rate of each link in real time.
set-opt-switch                 Enables optimized P4 switch.
set-non-opt-switch             Enables debugging P4 switch.
install-requirements [file]    Install python requirements for [file]
get-delay [node1] [node2]      Prints delay between two cities.
experiment-performance [path]  Prints every flow performance in [path]
    """
    return _help

if __name__ == "__main__":
    # get arguments
    args = sys.argv[1:]

    if len(args) < 1:
        print(help())
    else:
        # main commands
        cmd = args[0]
        if cmd == "help":
            print(help())
        elif cmd == "install-requirements":
            if len(args) < 2:
                print(help())
                sys.exit("Requirements file not found")
            path = args[1]
            install_requirements(path)
        elif cmd == "uninstall-requirements":
            path = args[1]
            uninstall_requirements(path)
        elif cmd == "get-delay":
            _project_topo_path = cur_dir + "/project/"
            if len(args) < 3:
                print(help())
                sys.exit("Not enough nodes")
            node1, node2 = args[1:]
            _delay = Delay(_project_topo_path)
            delay = _delay.get_delay(node1, node2)
            print("The delay between {} and {} is : {}ms".format(node1, node2, delay))
        elif cmd == "monitor":
            _topo_path = "/tmp/topology.json"
            monitor(_topo_path)
        elif cmd == "set-opt-switch":
            install_optimized_switch()
        elif cmd =="set-non-opt-switch":
            install_non_optimized_switch()
        elif cmd == "clean":
            path = args[1]
            clean_dir(path)
        elif cmd == "experiment-performance":
            # default output dir
            _output_dir = "./outputs"
            if len(args) > 1:
                _output_dir = args[1]
            experiment_performance(_output_dir)