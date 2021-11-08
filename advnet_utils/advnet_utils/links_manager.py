"""Schedule failure events."""

from typing import Dict, List, Tuple
from advnet_utils.network_API import AdvNetNetworkAPI
from advnet_utils.input_parsers import parse_link_failures
import networkx as nx


class InvalidFailure(Exception):
    """Invalid failure scenario exception"""
    pass


class LinksManager(object):
    """Failure manager."""
    max_attempts = 100
    workers = []

    def __init__(self, net: AdvNetNetworkAPI, failures_file: str, constrains: Dict[str, int], added_links: List[Tuple[str, str]]):

        # get networkx node topology
        self.net = net
        self.topo = net.g.convertTo(nx.Graph)
        self.switches = net.p4switches()
        self.topo = self.topo.subgraph(self.switches).copy()

        # get failures
        self.failures = parse_link_failures(failures_file)
        self.failures_raw = open(failures_file, "r").read()

        # links we added, this can be used to indicate we want to fail ADDED2
        self.added_links = added_links

        # replace ADDED by real link
        self._transform_added_to_real_link()

        # store failure constrains
        self.constrains = constrains

        # check if it is a valid failure scenario
        self._check_if_valid_failure_scenario()

        # Plan the link events from the provided spec
        self.link_events = self._get_link_events()

    # Scheduler failures.
    # ===================

    def set_reference_time(self, reference_time):
        """Sets the simulation t=0 to some specific unix time"""
        self.reference_time = reference_time

    def _enable_scheduler(self):
        """Enables the scheduler in some node at the main namespace"""
        # take the first switch
        if self.switches:
            self.namespace = self.switches[0]
        else:
            raise Exception(
                "Scheduler Error: There is 0 switches in the main namespace")

        self.net.enableScheduler(self.namespace)

    def _get_link_interfaces(self, node1, node2):
        """Get the real interfaces connecting two nodes"""
        intf1 = self.net.getLink(node1, node2)[0]["intfName1"]
        intf2 = self.net.getLink(node1, node2)[0]["intfName2"]
        return intf1, intf2

    def _get_link_event_cmd(self, intf, event):
        """Get link event cmd"""
        _cmd = "sudo ip link set dev {} {}".format(intf, event)
        # print(_cmd)
        return _cmd

    def _schedule_link_events(self, link_events):
        """Schedules all the link events (up/down)"""

        for event, (node1, node2), event_time in link_events:
            # get interface names
            intf1, intf2 = self._get_link_interfaces(node1, node2)
            # set start time in the future
            start_time = self.reference_time + event_time
            # get cmds
            _cmd1 = self._get_link_event_cmd(intf1, event)
            _cmd2 = self._get_link_event_cmd(intf2, event)
            # add commands
            self.net.addTask(self.namespace, _cmd1, start=start_time)
            self.net.addTask(self.namespace, _cmd2, start=start_time)

    def start(self, reference_time):
        """Starts and schedules the link events"""
        # Sets t=0 in the simulation
        self.set_reference_time(reference_time)
        # adds scheduler
        self._enable_scheduler()
        # Adds link events to task manager
        self._schedule_link_events(self.link_events)

    # Helpers to compute the failures from spec.
    # ==========================================

    def _transform_added_to_real_link(self):
        """Parses the failures and replaces ADDED by a real link if exists"""

        for i, (link, _, _) in enumerate(self.failures):
            if link[0].startswith("ADDED"):
                index = int(link[0].split("_")[-1]) - 1
                # if the index is invalid we also raise
                if index > 0 and index >= len(self.added_links):
                    raise InvalidFailure(
                        "Invalid Link Failure: Added link with index {} is invalid".format(index))
                real_link = self.added_links[index]
                self.failures[i][0] = real_link

    def _check_if_valid_failure_scenario(self):
        """Checks if the failure scenario holds constrains and keeps network connected"""

        self._assert_faliure_scenario()
        self._assert_network_connectivity()

    def _assert_faliure_scenario(self):
        """Do a basic check of the failure scenario"""

        # verify time budget
        total_fail_time = sum([x[2] for x in self.failures])
        if total_fail_time > self.constrains["time_budget"]:
            raise InvalidFailure("Exceeded Failure Budget: your total fail time is {}. Your budget is {}\n{}".format(
                total_fail_time, self.constrains["time_budget"], self.failures_raw))

        # verify start times and max fail time.
        for failure in self.failures:
            start_time = failure[1]
            duration = failure[2]
            end_time = start_time + duration
            # check if too early or too long
            if start_time < self.constrains["min_start"]:
                raise InvalidFailure("Invalid Link Failure (Too early) {}\n{}".format(
                    failure, self.failures_raw))
            if end_time > self.constrains["max_time"]:
                raise InvalidFailure("Invalid Link Failure (Too long): {}\n{}".format(
                    failure, self.failures_raw))

    def _assert_network_connectivity(self):
        """Checks if the network remains connected with the set of failures"""

        _link_events = self._get_link_events()
        # sort by event time
        _link_events_sorted = sorted(_link_events, key=lambda x: x[2])
        # valid sequence checking connectivity
        self._is_valid_link_event_sequence(_link_events_sorted)

    def _get_link_events(self):
        """Get all up/down events for the provided spec."""

        # events to schedule
        events = []
        for link, fail_time, duration in self.failures:
            events.append(("down", link, fail_time))
            events.append(("up", link, fail_time+duration))
        return events

    def _is_valid_link_event_sequence(self, events):
        """Checks if the sequence of events is valid"""

        # we apply events in batches. It could be that if one link goes down and
        # another up at the same time the network remains connected. If you
        # check events one by one you might trigger an Exception.

        # check if the network remains connected at any time

        # aggregate events
        _events = {}
        for action, edge, event_time in events:
            if event_time not in _events:
                _events[event_time] = [(action, edge)]
            else:
                _events[event_time].append((action, edge))

        # sort events by time
        _events = sorted(_events.items(), key=lambda x: x[0])

        for event_time, sub_events in _events:
            for action, edge in sub_events:
                if action == "down":
                    self.topo.remove_edge(*edge)
                elif action == "up":
                    self.topo.add_edge(*edge)

            # check if the graph is still connected
            if not nx.algorithms.components.is_connected(self.topo):
                raise InvalidFailure(
                    "Invalid Link Failure: Your failures disconnect the network!!!")
