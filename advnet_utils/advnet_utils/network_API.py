"""Small modification to p4utils network API"""

import time

from p4utils.mininetlib.network_API import NetworkAPI
from p4utils.utils.helper import load_topo, run_command
from p4utils.utils.task_scheduler import Task, TaskClient
from p4utils.mininetlib.log import setLogLevel, debug, info, output, warning, error


class AdvNetNetworkAPI(NetworkAPI):
    """Network definition and initialization API.

    Attributes:
        cli_enabled (:py:class:`bool`)              : enable an extension to *Mininet* CLI after the network starts.
        hosts (:py:class:`dict`)                    : dictionary of host and their properties.
        sw_clients (:py:class:`list`)               : list of *Thrift* clients (one per P4 switch) to populate tables.
        compilers (:py:class:`list`)                : list of compiler instances (one per P4 source provided) to compile P4 code.
        net (:py:class:`mininet.net.Mininet`)       : network instance implemented using an extension to *Mininet* network class.
        modules (:py:class:`dict`)                  : dictionary of external modules used by the API.
        ipv4_net (:py:class:`ipaddress.IPv4Network`): IPv4 network address generator (by default within the network ``10.0.0.0/8``).
                                                      a different network can be specified using :py:meth:`setIpBase()`.
        topoFile (:py:class:`str`)                  : path to the JSON topology database file.
        cpu_bridge (:py:class:`str`)                : name of the bridge used to connect all the CPU ports of the P4 switches.
        auto_gw_arp (:py:class:`bool`)              : automatically set gateways' MAC in the ARP tables of each host.
        auto_arp_tables (:py:class:`bool`)          : automatically populate the ARP tables of each hosts with MACs from the other
                                                      hosts present in the same subnetwork.
        scripts (:py:class:`list`)                  : list of script to execute in the main namespace.
        tasks (:py:class:`dict`)                    : dictionary containing scheduled tasks.
    """

    def __init__(self, *args, **params):
        super().__init__(*args, **params)

        self.waypoint_output = ""
        self.waypoint_switches = []

    def distribute_tasks(self):
        """Distributes all the tasks to the schedulers.

        **Assumes**

        - All the nodes in self.tasks have an active scheduler.
        - __ #p4utils.mininetlib.network_API.NetworkAPI.net

          A *Mininet* network instance is stored in the attribute ``net`` (see `here`__).
        - :py:meth:`self.net.start()` has been called.
        """
        for node, tasks in self.tasks.items():
            unix_path = self.getNode(node).get('unix_path', '/tmp')
            unix_socket = unix_path + '/' + node + '_socket'
            info('Tasks for node {} distributed to socket {}.\n'.format(
                node, unix_socket))
            task_client = TaskClient(unix_socket)
            task_client.send(tasks, retry=True)

        # Remove all the tasks once they are sent
        self.tasks = {}

    def configure_waypoint_captures(self, outputdir, switches):
        """Stores parameters that will be used by the set_waypoint filters function"""
        self.waypoint_output = outputdir
        self.waypoint_switches = switches

    def set_waypoint_filters(self, snapshot_length=250):
        """Sets the tcpdump filter for the waypointing"""
        
        topo = load_topo("/tmp/topology.json")
        # for every switch we set a filter for all interfaces
        for switch in topo.get_p4switches().keys():
            # if there is no waypoint rule we do not even monitor this switch
            if switch not in self.waypoint_switches:
                continue
            # get id, we use this for the pcap filter == tos
            switch_id = topo.get_p4switch_id(switch)
            # get all the interfaces that connect to P4 switch
            # I believe we do not need to capture node interfaces
            interfaces = []
            for neighbor in topo.get_p4switches_connected_to(switch):
                interfaces.append(topo.get_intfs()[switch][neighbor]["intfName"])

            # for some reason the filter only works 
            # in this direction: "ip[1]==0 or (mpls and ip[1]==0)"
            # add mpls filter recursively 
            # max 8 hops
            max_mpls_labels = 10
            cmd = "tcpdump -i {} -s {} --direction=in -w {} 'ip[1]=={}"
            for _ in range(max_mpls_labels):
                cmd +=  " or (mpls and ip[1]=={})"
            cmd += "' > /dev/null 2>&1 &"

            for interface in interfaces:
                switch_ids = [switch_id] * (max_mpls_labels + 1)
                out_name = self.waypoint_output + "/" + interface + ".pcap"
                _cmd = cmd.format(interface, snapshot_length, out_name, *switch_ids)
                #print(_cmd)
                run_command(_cmd)

    def startNetwork(self):
        """Starts and configures the network."""
        debug('Cleanup old files and processes...\n')
        self.cleanup()

        debug('Auto configuration of not configured interfaces...\n')
        self.auto_assignment()
        
        info('Compiling P4 files...\n')
        self.compile()
        output('P4 Files compiled!\n')

        self.printPortMapping()

        info('Creating network...\n')
        self.net = self.module('net', topo=self, controller=None)
        output('Network created!\n')

        info('Starting network...\n')
        self.net.start()
        output('Network started!\n')

        info('Starting schedulers...\n')
        self.start_schedulers()
        output('Schedulers started correctly!\n')

        info('Saving topology to disk...\n')
        self.save_topology()
        output('Topology saved to disk!\n')

        info('Add waypointing filters...\n')
        self.set_waypoint_filters()
        output('Waypointing filters added!\n')

        info('Programming switches...\n')
        self.program_switches()
        output('Switches programmed correctly!\n')

        info('Programming hosts...\n')
        self.program_hosts()
        output('Hosts programmed correctly!\n')
        
        info('Executing scripts...\n')
        self.exec_scripts()
        output('All scripts executed correctly!\n')

        info('Distributing tasks...\n')
        self.distribute_tasks()
        output('All tasks distributed correctly!\n')

        if self.cli_enabled:
            self.start_net_cli()
            # Stop right after the CLI is exited
            info('Stopping network...\n')
            self.net.stop()
            output('Network stopped!\n')