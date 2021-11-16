"""Schedule failure events."""

from typing import Dict, List
from advnet_utils.network_API import AdvNetNetworkAPI
from advnet_utils.input_parsers import parse_traffic
from advnet_utils.utils import setRateToInt, setSizeToInt, _parse_rate, _parse_size
from advnet_utils.traffic import send_tcp_flow, send_udp_flow, recv_tcp_flow, recv_udp_flow
import networkx as nx


class InvalidHost(Exception):
    pass


class InvalidTraffic(Exception):
    """Exceptions for input traffic"""
    pass

class TrafficManager(object):
    """Failure manager."""
    SENDERS_DURATION_OFFSET = 5

    def __init__(self, net: AdvNetNetworkAPI, additional_traffic_file, base_traffic_file, additional_constrains, base_constrains, check_constrains, outputdir, experiment_duration):

        # get networkx node topology
        self.net = net

        # checks 
        self.check_constrains = check_constrains

        # get additional traffic
        self._additional_traffic_file = additional_traffic_file
        self._additional_traffic = parse_traffic(additional_traffic_file)
        self._add_ips_to_traffic_flows(self._additional_traffic)
        # get additional traffic constrains
        self._additional_constrains: dict = additional_constrains

        # get base traffic\
        self._base_traffic_file = base_traffic_file
        self._base_traffic = parse_traffic(base_traffic_file)
        self._add_ips_to_traffic_flows(self._base_traffic)
        # get base traffic constrains
        self._base_constrains: dict = base_constrains

        # set out
        self.outputdir = outputdir

        # set experiment duration
        self.experiment_duration = experiment_duration

        if self.check_constrains:
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

    def _all_valid_hosts(self, flows, file_name):
        """Checks if all sender and receivers are valid"""

        hosts = self.net.hosts()
        for flow in flows:
            src = flow["src"]
            dst = flow["dst"]
            if src not in hosts:
                raise InvalidHost("Invalid traffic sender {}. Check input file {}".format(src, file_name))
            if dst not in hosts:
                raise InvalidHost("Invalid traffic receiver: {}. Check input file {}".format(dst, file_name))

    def _check_port_duplications(self, hosts, file_name):
        """Checks if there is any port duplicated in hosts"""

        # check if there is any port repetition
        for node, protocols in hosts.items():
            if len(protocols["udp"]) != len(set(protocols["udp"])):
                raise InvalidTraffic(
                    "Found duplicated ports in host {} (udp). Check input file {}".format(node, file_name))
            if len(protocols["tcp"]) != len(set(protocols["tcp"])):
                raise InvalidTraffic(
                    "Found duplicated ports in host {} (tcp). Check input file {}".format(node, file_name))

    def _check_if_ports_overlap(self, flows, file_name):
        """This function checks if there is any port overlap

        For every sender and receiver we make sure there is no overlapping port for a given protocol. With this we ensure we won't have problems.

        This is done in a global manner, thus, even if ports get freed, we consider them "used" for the entire simulation"
        """

        # build dictionaries to check
        senders = {}
        receivers = {}
        for flow in flows:
            # add to senders
            protocol = flow["protocol"]
            src = flow["src"]
            sport = flow["sport"]
            if src not in senders:
                senders[src] = {"udp": [], "tcp": []}
            if protocol not in senders[src]:
                senders[src][protocol] = []
            senders[src][protocol].append(sport)

            # add to receviers
            dst = flow["dst"]
            dport = flow["dport"]
            if dst not in receivers:
                receivers[dst] = {"udp": [], "tcp": []}
            if protocol not in receivers[dst]:
                receivers[dst][protocol] = []
            receivers[dst][protocol].append(dport)

        # check
        self._check_port_duplications(senders, file_name)
        self._check_port_duplications(receivers, file_name)

    def _check_port_range(self, port, low, high):
        """check if port in between (contained)"""
        if not (port >= low) and (port <= high):
            raise InvalidTraffic("Port {} is out of range: {}".format(port, (low, high)))
    
    def _flow_to_str(self, flow):
        """Returns string representation of a flow"""
        _str = "{} {} {} {} {}".format(flow["src"], 
                                        flow["dst"],
                                        flow["sport"],
                                        flow["dport"],
                                        flow["protocol"]
                                        )
        return _str

    def _check_flow_constrains(self, flows, constrains, file_name):
        """checks all flow constrains"""
        
        # Global Checks
        # check max flows
        _max_flows = constrains.get("max_flows", 0)
        if _max_flows > 0 and len(flows) > _max_flows:
            raise InvalidTraffic("Trying to schedule {} flows. Max is {}. Check input file {}".format(len(flows), _max_flows, file_name))

        # check max bandwidth traffic
        max_bytes = constrains.get("max_traffic", 0)
        max_bytes = setSizeToInt(max_bytes)
        # if 0 we have no constrain
        if max_bytes != 0:
            _flow_sizes_aggregated = sum(
                _parse_rate(x["rate"])*int(float(x["duration"])) for x in flows if x["protocol"] == "udp")
            if _flow_sizes_aggregated > max_bytes:        
                raise InvalidTraffic("Maxmimum aggregated size exceeded! {} > {}. Check input file {}".format(_flow_sizes_aggregated, max_bytes, file_name))
        
        # Per-flow checks
        for flow in flows:
            # check port range.
            _sport = flow["sport"]
            self._check_port_range(_sport, *constrains["port_range"])
            _dport = flow["dport"]
            self._check_port_range(_dport, *constrains["port_range"])

            # check protocol
            _protocol = flow["protocol"]
            if _protocol not in constrains["protocols"]:
                raise InvalidTraffic("{} is not a valid protocol. Check input file {}".format(_protocol, file_name))
            
            # checks for udp flows and tcp flows
            if _protocol == "udp" or _protocol == "tcp":       
                # check min start
                if flow["start_time"] < constrains["min_start"]:
                    raise InvalidTraffic("Invalid start time for flow: <{}>. Check input file {}".format(self._flow_to_str(flow), file_name))

                # checks if the start time is an integer
                if not float(flow["start_time"]).is_integer():
                    raise InvalidTraffic("Start time for flow <{}> is not an integer. Check input file {}.".format(self._flow_to_str(flow), file_name))

            # checks for only udp traffic
            if _protocol == "udp":
                # check min duration
                _duration = float(flow["duration"])
                if _duration < constrains["min_duration"]:
                    raise InvalidTraffic("Flow <{}> duration is too short. Check input file {}.".format(self._flow_to_str(flow), file_name))
                
                # checks if duration is an integer (we only allow integer durations, see constrains)
                if not float(_duration).is_integer():
                    raise InvalidTraffic("Flow <{}> duration is not an integer. Check input file {}.".format(self._flow_to_str(flow), file_name))

                # check max time
                if (flow["start_time"] + _duration) > constrains["max_time"]:
                    raise InvalidTraffic("Flow <{}> is too long. Check input file {}.".format(self._flow_to_str(flow), file_name))

                # check min rate
                _rate = _parse_rate(flow["rate"])
                _min_rate = _parse_rate(constrains["min_rate"])
                if _rate < _min_rate:
                    raise InvalidTraffic("Flow <{}> rate is too small. Check input file {}.".format(self._flow_to_str(flow), file_name))      
                # check max rate        
                _max_rate = _parse_rate(constrains["max_rate"])
                if _rate > _max_rate:
                    raise InvalidTraffic("Flow <{}> is too big. Check input file {}.".format(self._flow_to_str(flow), file_name))


    def _check_if_valid_additional_traffic(self):
        """Checks if additional traffic is valid"""

        # check if there is no port overlap
        self._check_if_ports_overlap(self._additional_traffic, self._additional_traffic_file)
        # check if valid hosts
        self._all_valid_hosts(self._additional_traffic, self._additional_traffic_file)
        # checl all constrains
        self._check_flow_constrains(self._additional_traffic, self._additional_constrains, self._additional_traffic_file)

    def _check_if_valid_base_traffic(self):
        """Checks if base traffic is valid"""

        # check if there is no port overlap
        self._check_if_ports_overlap(self._base_traffic, self._base_traffic_file)
        # check if valid hosts
        self._all_valid_hosts(self._base_traffic, self._base_traffic_file)
        # checl all constrains
        self._check_flow_constrains(self._base_traffic, self._base_constrains, self._base_traffic_file)


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
            # start all receivers before reference time! 
            receiver_start_time = self.reference_time - 5 # start receivers 5 sec before.
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
