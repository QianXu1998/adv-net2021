"""Small modification to p4utils network API"""

import time

from p4utils.mininetlib.network_API import NetworkAPI
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
