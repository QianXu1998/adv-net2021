"""Schedule failure events."""

from typing import Dict, List
from advnet_utils.network_API import AdvNetNetworkAPI
from advnet_utils.input_parsers import parse_traffic
from advnet_utils.utils import setRateToInt, setSizeToInt
from advnet_utils.traffic import send_tcp_flow, send_udp_flow, recv_tcp_flow, recv_udp_flow
import networkx as nx


class InvalidHost(Exception):
    pass


class InvalidAdditionalTraffic(Exception):
    """Exceptions for additional traffic"""
    pass


class InvalidBaseTraffic(Exception):
    """Exceptions for additional traffic"""
    pass


class TrafficManager(object):
    """Failure manager."""
    workers = []
    SENDERS_DURATION_OFFSET = 5

    def __init__(self, net: AdvNetNetworkAPI, additional_traffic_file, base_traffic_file, additional_constrains, base_constrains, outputdir, experiment_duration):

        # get networkx node topology
        self.net = net

        # get additional traffic
        self._additional_traffic = parse_traffic(additional_traffic_file)
        self._add_ips_to_traffic_flows(self._additional_traffic)
        # get additional traffic constrains
        self._additional_constrains: dict = additional_constrains

        # get base traffic
        self._base_traffic = parse_traffic(base_traffic_file)
        self._add_ips_to_traffic_flows(self._base_traffic)
        # get base traffic constrains
        self._base_constrains: dict = base_constrains

        # set out
        self.outputdir = outputdir

        # set experiment duration
        self.experiment_duration = experiment_duration

        # check if there is no port overlap
        self._check_if_ports_overlap()

        # check additional traffic validity.
        self._check_if_valid_additional_traffic()

        # check base traffic validity.
        self._check_if_valid_base_traffic()

    def _node_to_ip(self, node):
        """Get the ip address of a node"""

        ip = self.net.getNode(node)["ip"]
        ip = ip.split("/")[0]
        return ip

    def _add_ips_to_traffic_flows(self, flows):
        """Add src and dst ips of each node"""
        for flow in flows:
            flow["src_ip"] = self._node_to_ip(flow["src"])
            flow["dst_ip"] = self._node_to_ip(flow["dst"])

    # Sanity checks for traffic matrices.
    # ===================================

    def _all_valid_hosts(self):
        """Checks if all sender and receivers are valid"""

        hosts = self.net.hosts()
        for flow in self._additional_traffic:
            src = flow["src"]
            dst = flow["dst"]
            if src not in hosts:
                raise InvalidHost("Invalid traffic sender {}".format(src))
            if dst not in hosts:
                raise InvalidHost("Invalid traffic receiver: {}".format(dst))

    def _check_udp_bw_constrain(self, flows):
        """Check if traffic fulfills bw constrain"""

        max_bytes = self._additional_constrains.get("max_traffic", 0)
        max_bytes = setSizeToInt(max_bytes)

        # if 0 we have no constrain
        if max_bytes != 0:
            _flow_sizes_aggregated = sum(
                setRateToInt(x["rate"]) for x in flows)
            if _flow_sizes_aggregated > max_bytes:
                return False

        return True

    def _check_port_duplications(self, hosts):
        """Checks if there is any port duplicated in hosts"""

        # check if there is any port repetition
        for node, protocols in hosts.items():
            if len(protocols["udp"]) != len(set(protocols["udp"])):
                raise Exception(
                    "Found duplicated ports in {} for udp flows".format(node))
            if len(protocols["tcp"]) != len(set(protocols["tcp"])):
                raise Exception(
                    "Found duplicated ports in {} for tcp flows".format(node))

    def _check_if_ports_overlap(self):
        """This function checks if there is any port overlap

        For every sender and receiver we make sure there is no overlapping port for a given protocol. With this we ensure we won't have problems.

        This is done in a global manner, thus, even if ports get freed, we consider them "used" for the entire simulation"
        """

        # build dictionaries to check
        senders = {}
        receivers = {}
        for flow in self._additional_traffic:
            # add to senders
            protocol = flow["protocol"]
            src = flow["src"]
            sport = flow["sport"]
            senders.setdefault(src, {"udp": [], "tcp": []})[
                protocol].append(sport)

            # add to receviers
            dst = flow["dst"]
            dport = flow["dport"]
            receivers.setdefault(dst, {"udp": [], "tcp": []})[
                protocol].append(dport)

        # check
        self._check_port_duplications(senders)
        self._check_port_duplications(receivers)

    def _check_if_valid_additional_traffic(self):
        """Checks if additional traffic is valid"""

        # check if valid hosts
        self._all_valid_hosts()

        # check if all flows are udp
        _all_udp = all(x["protocol"] ==
                       "udp" for x in self._additional_traffic)

        # check bandwidth budget

        # check traffic is not scheduled after the max time.

        # maybe some checks on ports.

    def _check_if_valid_base_traffic(self):
        """Checks if base traffic is valid"""

        self._all_valid_hosts()

        # check bandwidth budget

        # check traffic is not scheduled after the max time.
        # TODO: how will we do this for TCP?

        # maybe some checks on ports.

    # Schedule Flows.
    # ===============

    def set_reference_time(self, reference_time):
        """Sets the simulation t=0 to some specific unix time"""
        self.reference_time = reference_time

    def _enable_schedulers(self):
        """Enables the scheduler in all the hosts"""
        # take the first switch
        self.hosts = self.net.hosts()
        for host in self.hosts:
            self.net.enableScheduler(host)

    @staticmethod
    def _get_out_file_name(flow):
        """Serializes flow to string"""
        outfile = "{}_{}_{}_{}_{}".format(
            flow["src"], flow["dst"], flow["sport"], flow["dport"], flow["protocol"])
        return outfile

    def _schedule_flows(self, flows):
        """Scheduler flows (senders and receivers)"""
        for flow in flows:
            sender_start_time = self.reference_time + flow["start_time"]
            # max sender duration time
            sender_duration_time = self.experiment_duration - \
                flow["start_time"]
            # we start receivers at simulation t=0
            receiver_start_time = self.reference_time
            # assuming all receivers start at 0, we make duration ~65 sec.
            receivers_duration = self.experiment_duration + \
                TrafficManager.SENDERS_DURATION_OFFSET
            # get flow signature for the outputs
            flow_str = self._get_out_file_name(flow)
            if flow["protocol"] == "udp":
                # set sender kargs
                sender_kwargs = {"dst": flow["dst_ip"], "sport": flow["sport"],
                                 "dport": flow["dport"], "rate": flow["rate"], "duration": float(flow["duration"]), "out_csv": self.outputdir + "/send-{}.csv".format(flow_str)}
                # set receiver kwargs
                receiver_kwargs = {"sport": flow["sport"], "dport": flow["dport"],
                                   "duration": receivers_duration, "out_csv": self.outputdir + "/recv-{}.csv".format(flow_str)}
                _send_function = send_udp_flow
                _recv_function = recv_udp_flow
            elif flow["protocol"] == "tcp":
                sender_kwargs = {"dst": flow["dst_ip"], "sport": flow["sport"],
                                 "dport": flow["dport"], "send_size": flow["size"], "duration": sender_duration_time, "out_csv": self.outputdir + "/send-{}.csv".format(flow_str)}
                # set receiver kwargs
                receiver_kwargs = {"sport": flow["sport"], "dport": flow["dport"],
                                   "duration": receivers_duration, "out_csv": self.outputdir + "/recv-{}.csv".format(flow_str)}
                _send_function = send_tcp_flow
                _recv_function = recv_tcp_flow

            # add tasks
            self.net.addTask(flow["src"], _send_function,
                             start=sender_start_time, kwargs=sender_kwargs)
            self.net.addTask(flow["dst"], _recv_function,
                             start=receiver_start_time, kwargs=receiver_kwargs)

    def start(self, reference_time):
        """Starts and schedules the link events"""
        # Sets t=0 in the simulation
        self.set_reference_time(reference_time)
        # adds scheduler
        self._enable_schedulers()
        # Adds flow events to the scheduler
        self._schedule_flows(self._additional_traffic)
        self._schedule_flows(self._base_traffic)
