#!/usr/bin/env python

"""Adv-net 2021 project cli"""
import os, sys
import time

from advnet_utils.utils import install_requirements, uninstall_requirements, install_non_optimized_switch, install_optimized_switch, clean_dir

# CLI
# ==========

def monitor():
    """Start monitoring"""
    print("Utility under development")

def clean():
    pass


def help():
    _help = """
    Usage: ./cli.py COMMAND [ARGS...]

    Commands:
    =========
    help 
    install-requirements [path]
    uninstall-requirements [path]
    get-delay [node1] [node2]
    monitor 
    set-opt-switch
    set-non-opt-switch
    clean [path]
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
            path = args[1]
            install_requirements(path)
        elif cmd == "uninstall-requirements":
            path = args[1]
            uninstall_requirements(path)
        elif cmd == "get-delay":
            _topo_path = "/home/p4/p4-tools/infrastructure/project/"
            node1, node2 = args[2:]
        elif cmd == "monitor":
            monitor()
        elif cmd == "set-opt-switch":
            install_optimized_switch()
        elif cmd =="set-non-opt-switch":
            install_non_optimized_switch()
        elif cmd == "clean":
            path = args[1]
            clean_dir(path)