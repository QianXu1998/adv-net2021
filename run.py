"""Adv-net 2021 project runner"""

"""
Usage: sudo python3 run.py 
"""
from logging import debug
import os
import argparse
import time

from advnet_utils.network_API import AdvNetNetworkAPI
from advnet_utils.links_manager import LinksManager
from advnet_utils.traffic_manager import TrafficManager
from threading import Thread

# get current path
cur_dir = os.path.dirname(os.path.abspath(__file__)) + "/"
from advnet_utils.topology_builder import build_base_topology, add_links_to_topology
from advnet_utils.utils import load_constrains, wait_experiment

def run_controllers(net: AdvNetNetworkAPI, inputidr):
    """Schedules controllers

    The controller code must be placed in `inputdir/controllers/`

    You are allowed to run a maximum of one controller per node and one global controller. In general, you should be able to do everything with one single
    controller.

    The global controller must be called: controller.py Per switch controllers
    must be called: <switch_name>-controller.py. For example: BAR-controller.py
    
    """
    # path
    controllers_dir = inputidr + "/controllers/"
    # schedule global controller if exists.
    if os.path.isfile(controllers_dir + "controller.py"):
        net.execScript(
            'python {}/controller.py > /dev/null &'.format(controllers_dir), reboot=True)
    # schedule other controllers
    for switch_name in net.p4switches():
        if os.path.isfile(controllers_dir + "{}-controller.py".format(switch_name)):
            net.execScript(
                'python {}/{}-controller.py > /dev/null &'.format(controllers_dir, switch_name), reboot=True)

def program_switches(net: AdvNetNetworkAPI, inputdir):
    """Programs switches 

    The p4 code must be placed in `inputdir/p4src/`

    As with the controllers, you are allowed allowed to program each switch with
    a different program. Or use the same program for every switch.

    The default P4 code must be called: switch.p4. If you want a specific switch
    to have special code you must name it <switch-name>.p4.
    """
    # path
    p4src_dir = inputdir + "/p4src/"
    for switch_name in net.p4switches():
        p4src_path =p4src_dir + "{}.p4".format(switch_name)
        if os.path.isfile(p4src_path):
            net.setP4Source(switch_name, p4src_path)
        else: # default program
            net.setP4Source(switch_name, p4src_dir + "/switch.p4")


def run_network(inputdir, scenario, outputdir, debug_mode, log_enabled, pcap_enabled, warmup_phase=5):

    # starts the flow scheduling task
    net = AdvNetNetworkAPI()
    # Network general options
    net.setLogLevel('info')
    # build base topology
    build_base_topology(net, topology_path=cur_dir + "/project/")
    # add cpu port
    # this might be useful to copy to cpu or send traffic to the switches.
    net.enableCpuPortAll()
    # set P4 programs
    program_switches(net, inputdir)
    # load constrains
    project_constrains = load_constrains(cur_dir + "/project/constrains.json")
    
    # add additional links
    _add_links_constrains = project_constrains["add_links_constrains"]
    _topology_path = cur_dir + "/project/"
    _links_file = inputdir + "/inputs/" + "{}.links".format(scenario)
    _added_links = add_links_to_topology(
        net, topology_path=_topology_path, links_file=_links_file, 
        constrains=_add_links_constrains)

    # Assignment strategy
    net.mixed()
    # atuo assign to get more info
    net.auto_assignment()

    # Start Simulation in the future
    simulation_time_reference = time.time() + warmup_phase

    # schedule link failures
    _failure_constrains = project_constrains["failure_constrains"]
    _failures_file = inputdir + "/inputs/" + "{}.failure".format(scenario)
    links_manager = LinksManager(net, failures_file=_failures_file,
                 constrains=_failure_constrains, added_links=_added_links)
    # schedules link events
    links_manager.start(simulation_time_reference)

    # Schedule Traffic
    # clean output dir
    if outputdir == "/":
        raise Exception("Trying to remove all disk!!")
    os.system("rm -rf {}".format(outputdir))
    os.system("mkdir -p {}".format(outputdir))

    _additional_traffic_constrains = project_constrains["additional_traffic_constrains"]
    _base_traffic_constrains = project_constrains["base_traffic_constrains"]
    _additional_traffic_file = inputdir + "/inputs/" + \
        "{}.traffic-additional".format(scenario)
    _base_traffic_file = inputdir + "/inputs/" + \
        "{}.traffic-base".format(scenario)
    # get max traffic type for additional and base traffic to guess the experiment duration
    experiment_duration = max(_additional_traffic_constrains.get(
        "max_time", 0), _base_traffic_constrains.get("max_time", 0))
    traffic_manager = TrafficManager(net, _additional_traffic_file,
                                     _base_traffic_file, _additional_traffic_constrains, 
                                     _base_traffic_constrains, outputdir, experiment_duration)
    # schedule flows                                    
    traffic_manager.start(simulation_time_reference)

    # Adds controllers.
    run_controllers(net, inputdir)

    # enable or disable logs and pcaps
    if log_enabled:
        net.enableLogAll()
    else:
        net.disableLogAll()
    if pcap_enabled: # not recommended 
        net.enablePcapDumpAll()
    else:
        net.disablePcapDumpAll()
    
    # sets debug mode
    if debug_mode:
        # enable cli
        net.enableCli()
    else:
        # disable cli
        net.disableCli()

    # Start network
    net.startNetwork()

    # wait for experiment to finish
    if not debug_mode:
        wait_experiment(simulation_time_reference, experiment_duration)
      
# MAIN Runner
# ==========


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--inputdir', help='Path to all inputs (controllers, p4src)',
                        type=str, required=False, default='./')
    parser.add_argument('--scenario', help='Path to all input events (links, failures, traffic)',
                        type=str, required=False, default='test')
    parser.add_argument('--warmup', help='Time before starting the simulation',
                        type=float, required=False, default=5)
    parser.add_argument('--outputdir', help='Path were the experiment outputs will be saved. If it exists, all content is erased',
                        type=str, required=False, default='./outputs/')
    parser.add_argument('--debug-mode', help='Runs topology indefinetely',
                        action='store_true', required=False, default=False)
    parser.add_argument('--log-enabled', help='Enables logging',
                        action='store_true', required=False, default=False)
    parser.add_argument('--pcap-enabled', help='Enables pcap captures (not recommended)',
                        action='store_true', required=False, default=False)
    return parser.parse_args()


if __name__ == "__main__":
    args = get_args()
    run_network(args.inputdir, args.scenario, args.outputdir, args.debug_mode,
                args.log_enabled, args.pcap_enabled, float(args.warmup))
