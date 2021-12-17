"""Template of an empty global controller"""
import argparse
import csv
from advnet_utils.input_parsers import parse_traffic
from advnet_utils.sla import cleanfile, make_sla
from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
from enum import IntEnum
import logging
import numpy as np
import threading
import binascii
import struct
import time
import socket
import nnpy
from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
from datetime import datetime
from thrift.Thrift import TApplicationException
from thrift.transport.TTransport import TTransportException
import copy
import psutil

# TODO: remove logging to speedup
logging.basicConfig(filename='/tmp/controller.log', format="[%(levelname)s] %(message)s", level=logging.DEBUG)

# Some naming convention:
#   c1 -> city1
#   c2 -> city2
#   sw -> switch
#   sw1 -> switch1
#   sw2 -> switch2


# This class assign a numberic index to each city. Since it is derived fron IntEnum, each enum can be used like
# a python int. Also, a python int can be used to construct a City class.
#
# In [27]: c1 = City.AMS
#
# In [28]: print(str(c1))
# AMS
#
# In [29]: c1 == 0
# Out[29]: True
#
# In [30]: c1 == City(0)
# Out[30]: True
class City(IntEnum):
    AMS = 0
    BAR = 1
    BER = 2
    BRI = 3
    EIN = 4
    FRA = 5
    GLO = 6
    LIL = 7
    LIS = 8
    LON = 9
    MAD = 10
    MAN = 11
    MUN = 12
    PAR = 13
    POR = 14
    REN = 15

    def __str__(self):
        s = super().__str__()

        return s.split(".")[1]

# This map a city string to a City enum.
city_maps = {
    "AMS" : City.AMS,
    "BAR" : City.BAR,
    "BER" : City.BER,
    "BRI" : City.BRI,
    "EIN" : City.EIN,
    "FRA" : City.FRA,
    "GLO" : City.GLO,
    "LIL" : City.LIL,
    "LIS" : City.LIS,
    "LON" : City.LON,
    "MAD" : City.MAD,
    "MAN" : City.MAN,
    "MUN" : City.MUN,
    "PAR" : City.PAR,
    "POR" : City.POR,
    "REN" : City.REN,
}

# Represent a P4Swtich
class Switch:

    def __init__(self, city: City):
        # The city this switch belongs to
        self.city = city
        # The links this switch have, note the key type is City and it doesn't include the link to host.
        # The dict keys of the inner dict are:
        #      "port", "delay", "mac", "sw", "bw", "interfaces"
        # See build_topo for details
        self.sw_links = {} # type: dict[City, dict[str]]
        # This ports this switch have, note the key type is int (port number) and it doesn't include the port host connected to.
        self.sw_ports = {} # type: dict[int, Switch]
        # The host connected to this switch
        self.host = Host(self)
        # The controller API
        self.controller = None # type: SimpleSwitchThriftAPI
        # The path to other hosts.
        self.hosts_path = [ ( (), 0xFFFF ) for _ in range(16) ]
        # The links that are failed on this switch.
        self.failed_link = []
        self.in_reroute_table = {}

    def get_link_to(self, city: City):
        """
            Get a link to the city.

            Note the city must be connected to the switch.
        """
        next_sw = self.sw_links[city]['sw']
        return self.sw_links[city]['port'], self.sw_links[city]['mac'], next_sw.sw_links[self.city]['port'], next_sw.sw_links[self.city]['mac']

    def table_add(self, table_name: str, action_name: str, match_keys: list, action_params: list, prio=0):
        """
            The wrapper for table_add command.
        """
        r = self.controller.table_add(table_name, action_name, match_keys, action_params, prio)
        #logging.debug(f"[{str(self)}] table_add {table_name} {action_name} {match_keys} {action_params} {prio} ret={r}")
        
        if r is None:
            pass
            #logging.warning(f"[{str(self)}] table_add ret is None!")
        return r

    def table_modify(self, table_name: str, hdl: int, action_name: str, action_params: list):
        """
            The wrapper for table_modify command.
        """
        r = self.controller.table_modify(table_name, action_name, hdl, action_params)
        #logging.debug(f"[{str(self)}] table_modify {table_name} {action_name} {action_params} hdl={hdl} ret={r}")
        return r

    def dst_table_add(self, dst: City, table_name: str, action_name: str, match_keys: list, action_params: list, best_path: list):
        """
            Add a new table entry for routing to the destination City.

            This function is mostly used for reroute. If the `best_path` is already the path to the destination City, 
            nothing happens. Else, we do a table_modify.
        """
        last_path, last_hdl = self.hosts_path[dst]
        if last_hdl == 0xFFFF:
            hdl = self.table_add(table_name, action_name, match_keys, action_params)
            if hdl is not None:
                self.hosts_path[dst] = (best_path, hdl)
            return hdl
        else:
            if best_path != last_path:
                hdl = self.table_modify(table_name, last_hdl, action_name, action_params)
                self.hosts_path[dst] = (best_path, hdl)
                logging.debug(f"[{str(self)}] -> [{str(dst)}] Path Change (hdl={hdl} last_hdl={last_hdl}):\n{last_path}\n{best_path}")
                return hdl
            return last_hdl

    def get_meter_rates_from_bw(self, bw_committed, burst_size_committed, bw_peak, burst_size_peak):
        """
            This function calculates the rates parameter for meter_set_rates API,
            rates is a list with the format : [(CIR, CBS), (PIR, PBS)]
            CIR and PIR are the bucket filling rate per **microsecond**
            e.g. CIR = 1 -> 1000000 Bytes/s 

            Args:
                bw (float): desired bandwidth in mbps
                burst_size (int, can be optional): Max capacity of the meter bucket.
            
            Returns:
                rates(Bytes/s)
        """
        rates = []
        rates.append((0.125 * bw_committed, burst_size_committed))
        rates.append((0.125 * bw_peak, burst_size_peak))

        return rates

    def set_direct_meter_bandwidth(self, meter_name: str, handle: int, bw_committed: float, bw_peak: float, burst_committed: float, burst_peak: float):
        try:
            rates = self.get_meter_rates_from_bw(bw_committed, burst_committed, bw_peak, burst_peak)
            self.controller.meter_set_rates(meter_name, handle, rates)
        except TTransportException:
            logging.exception("Fail to set meter")

    @property
    def host_port(self):
        """
            This attribute represents the port which is connected to the host.
        """
        return self.host.sw_port

    def __str__(self):
        """
            For pretty print.
        """
        return str(self.city)

# Represent the host connected to the switch.
class Host:
    def __init__(self, sw: Switch):
        # The swtich the host connected to
        self.city_sw = sw # type: Switch
        # The mac address
        self.mac = None # type: str
        # The lpm representation of ip address. e.g. 192.168.1.0/24
        self._lpm = None # type: str
        # The ip address. e.g. 192.168.1.0/32
        self._ip = None # type: str
        self.sw_port = None # type: int
        self.sw_interface = None # type str
    
    @property
    def lpm(self):
        return self._lpm

    @lpm.setter
    def lpm(self, l):
        self._lpm = l
        self._ip = l.split("/")[0]

    @property
    def ip(self):
        return self._ip

    def __str__(self) -> str:
        return f"{str(self.city_sw)}_h0"

# The threads to send heartbeat with a fixed interval.
# The direction is sw1->sw2
class Ping(threading.Thread):

    def __init__(self, sw1: Switch, sw2: Switch, interval: float):
        super().__init__()
        self.sw1 = sw1
        self.sw2 = sw2
        self.interval = interval

    def build_hearbeat(self):
        """
            Build a heartbeat frame.

            From headers.p4:
                header heart_t {
                    bit<9>    port;
                    bit<1>    from_cp;
                    bit<6>    padding;
                }
        """
        s1_port, s1_mac, _, s2_mac = self.sw1.get_link_to(self.sw2.city)
        bs = b""
        bs += b"".join(map(binascii.unhexlify, s2_mac.split(":")))
        bs += b"".join(map(binascii.unhexlify, s1_mac.split(":")))
        bs += struct.pack(">H", 0x1926)
        bs += struct.pack(">H", (s1_port << 7) | (1 << 6))

        return bs


    def run(self):
        inf1, inf2 = self.sw1.sw_links[self.sw2.city]['interfaces']

        while True:
            skt = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            try:
                skt.bind((inf1, 0))
                bs = self.build_hearbeat()
                logging.debug(f"[{str(self.sw1)}] -> [{str(self.sw2)}]: Sniffing {inf1}")
                while True:
                    try:
                        skt.send(bs)
                        time.sleep(self.interval)
                    except OSError as e:
                        if e.errno == 105:
                            # Bandwith full, nothing more to do
                            time.sleep(self.interval)
                        else:
                            # Re-raise the error
                            raise e
            except KeyboardInterrupt:
                return
            except OSError as e:
                
                # We are done, the device doesn't exist any more
                if e.errno == 19 or e.errno == 6:
                    return
                else:
                    # 100: Link down
                    if e.errno != 100:
                        logging.exception(f"[{str(self.sw1)}] -> [{str(self.sw2)}] inf1={inf1} inf2={inf2}")
                    # Sleep and try again.
                    time.sleep(self.interval)
            except Exception:
                logging.exception(f"[{str(self.sw1)}] -> [{str(self.sw2)}] inf1={inf1} inf2={inf2}")
            finally:
                skt.close()
            

# The Pong monitor which report a link failure
class Pong(threading.Thread):

    def __init__(self, sw: Switch, threshold: float, failure_cb: callable, good_cb: callable):
        super().__init__()
        self.sw = sw
        self.failure_cb = failure_cb
        self.good_cb = good_cb
        self.threshold = threshold
        self.latest_timestamp = 0
        self.last_seen = [None for _ in range(16)]

    def process_stamps(self, raw_stamps: list):
        for port, stamp in enumerate(raw_stamps):
            if port not in self.sw.sw_ports or stamp == 0:
                continue
            if stamp > self.latest_timestamp:
                self.latest_timestamp = stamp

            self.last_seen[port] = stamp

    def run(self):
        try:
            while True:
                try:
                    time.sleep(self.threshold)
                    # Read the register directly.
                    register_stamps = self.sw.controller.register_read("linkStamp")
                    self.process_stamps(register_stamps)
                except OSError as e:

                    # We are done, the switch is offline.
                    if e.errno == 32:
                        return
                except TApplicationException:
                    # Sometimes we get this exception.
                    # I suspect it is caused by multithreading.
                    pass
                finally:
                    fports = []
                    gports = []
                    if self.latest_timestamp != 0:
                        for p in self.sw.sw_ports:
                            if self.last_seen[p] is not None:
                                if (self.latest_timestamp - self.last_seen[p]) / 1e6 > self.threshold:
                                    fports.append(p)
                                else:
                                    gports.append(p)
                    
                    # Report the up and down ports.
                    if len(fports) != 0:
                        self.failure_cb(self, fports)

                    if len(gports) != 0:
                        self.good_cb(self, gports)
        except KeyboardInterrupt:
            return
        except Exception:
            logging.exception("")


# The flow monitor use scapy to monitor all flows to trigger a possible reroute.
class FlowMonitor(threading.Thread):

    def __init__(self, switches: list, spd_cb: callable, interval=0.5):
        super().__init__()
        self.switches = switches
        self.spd_cb = spd_cb
        self.interval = interval
        self.last_time = None
        self.flows = { City(i) : {} for i in range(16) }
        self.interfaces = {sw.host.sw_interface : sw for sw in self.switches}
        self.hosts = {sw.host.ip : sw for sw in self.switches}

    def parse(self, pkt: Packet):
        
        iface = pkt.sniffed_on
        if iface is None:
            return

        if iface not in self.interfaces:
            logging.warning(f"Packet on {iface} not in {self.interfaces}")
            return

        city = self.interfaces[iface].city
        ip = pkt.getlayer(IP)

        if ip is not None:
            tcp = pkt.getlayer(TCP)
            udp = pkt.getlayer(UDP)

            if tcp is None and udp is None:
                return
            
            if tcp is not None:
                sport = tcp.sport
                dport = tcp.dport
                proto = "tcp"
            else:
                sport = udp.sport
                dport = udp.dport
                proto = "udp"

            # src_ip = get_field_bytes(ip, "src")
            # dst_ip = get_field_bytes(ip, "dst")
            src_ip = ip.src
            if src_ip not in self.hosts:
                logging.warning(f"src_ip={src_ip} not in {self.hosts}")
                return
            src_city = self.hosts[src_ip].city
            dst_ip = ip.dst
            if dst_ip not in self.hosts:
                logging.warning(f"dst_ip={dst_ip} not in {self.hosts}")
                return
            dst_city = self.hosts[dst_ip].city

            fl = (src_city, sport, dst_city, dport, proto)

            if fl not in self.flows[city]:
                self.flows[city][fl] = 0

            whole_size = len(pkt)
            self.flows[city][fl] += whole_size
        
        now = pkt.time

        if now - self.last_time > self.interval:
            try:
                # Report all flows.
                self.spd_cb(self, self.flows, now - self.last_time)
            except Exception:
                logging.exception(f"Fail to call spd_cb")
            self.last_time = now
            self.flows = { City(i) : {} for i in range(16) }

    def run(self):
        self.last_time = datetime.now().timestamp()
        logging.debug(f"Monitor flow on: {list(self.interfaces.keys())}")
        try:
            sniff(iface=list(self.interfaces.keys()), prn=self.parse)
        except Exception:
            logging.exception("Fail to monitor flow")

# The core controller object
class Controller(object):

    def __init__(self, base_traffic: str, slas: str):
        self.base_traffic_file = base_traffic
        self.slas_file = slas
        self.topo = load_topo('topology.json')
        self.controllers = {}
        self.links_capacity = [ [0 for __ in range(16)] for _ in range(16) ]
        self.weights = { City(i) : {} for i in range(16) }
        self.switches = [Switch(City(i)) for i in range(16)]
        self.all_available_path = []
        self.thrift_controller = None
        self.wps = [ [None for __ in range(16)] for _ in range(16) ]
        self.init()

    def parse_inputs(self):
        """
            Parse the inputs with utils TAs provide.
        """
        with open(self.slas_file, "r+") as f:
            rdr = csv.DictReader(cleanfile(f))
            self.slas = [make_sla(spec) for spec in rdr]
        self.flows = parse_traffic(self.base_traffic_file)

    def parse_city_str(self, s: str):
        """
            Parse the city string in the csv file.

            Note: None(*) -> all cities.
        """
        if s is None:
            return [City(i) for i in range(16)]
        return [city_maps[s.split("_")[0]]]

    def parse_port_range(self, tp: tuple):
        """
            Parse the port range in the csv file.

            Note: None(*) -> 0 / 65535
        """
        l, r = tp
        if l is None:
            l = 0
        else:
            l = int(l)
        if r is None:
            r = 65535
        else:
            r = int(r)
        
        return (l, r)

    def build_sla_rules(self):
        """
            This function build rules for specific SLAs.
        """
        try:
            for sla_idx, sla in enumerate(self.slas):
                src_cities = self.parse_city_str(sla.src)
                dst_cities = self.parse_city_str(sla.dst)

                src_l, src_r = self.parse_port_range(sla.sport)
                dst_l, dst_r = self.parse_port_range(sla.dport)

                prot = sla.protocol

                if prot == "udp":
                    tname = "udp_sla"
                else:
                    tname = "tcp_sla"

                logging.debug(f"sla: {sla.type} {src_l} {src_r} {dst_l} {dst_r}")

                # Port range 301-400 UDP is blocked.
                if src_r == 400 and prot != "tcp":
                    continue
                
                # Port range 101-400 TCP is blocked.
                if src_l <= 400 and src_l >= 101 and prot == "tcp":
                    continue
                
                # Port range 60001-* is blocked.
                if src_l == 60001 and prot == "udp":
                    continue
                
                # Note: all waypoints traffic is allowed

                for src_city in src_cities:
                    sw1 = self.switches[src_city] # type: Switch
                    
                    for dst_city in dst_cities:
                        if src_city != dst_city:
                            sw2 = self.switches[dst_city] # type: Switch

                            # Add rules for range sport=[src_l, src_r] dport=[dst_l, dst_r]
                            sw1.table_add(tname, "NoAction", [str(sw1.host.sw_port), sw2.host.lpm, f"{src_l}->{src_r}", f"{dst_l}->{dst_r}"], [], 1 + int(dst_city) + sla_idx * len(self.slas))
                            sw2.table_add(tname, "NoAction", [str(sw2.host.sw_port), sw1.host.lpm, f"{dst_l}->{dst_r}", f"{src_l}->{src_r}"], [], 1 + int(dst_city) + sla_idx * len(self.slas))

            
            for sw in self.switches:

                for p in sw.sw_ports.keys():
                    # Add rules for forwarding.
                    # Equavelent to
                    #   iptables -A FORWARD -j ACCEPT
                    sw.table_add("tcp_sla", "NoAction", [str(p), "0.0.0.0/0", "0->65535", "0->65535"], [], 0)
                    sw.table_add("udp_sla", "NoAction", [str(p), "0.0.0.0/0", "0->65535", "0->65535"], [], 0)

                # By defacult block all traffic.
                # Equavelent to
                #   iptables -P INPUT DROP
                sw.controller.table_set_default("tcp_sla", "drop")
                sw.controller.table_set_default("udp_sla", "drop")

        except Exception:
            logging.exception("Adding sla")
            
    def init(self):
        """
            1. Build the topo and the data structures we would use
            2. Parse and build sla rules.
            3. Build the best paths based on SLA.
        """
        self.connect_to_switches()
        self.reset_states()
        self.build_topo()
        self.sanity_check()
        self.parse_inputs()
        self.build_sla_rules()

        self.paths = self.cal_paths()
        self.best_paths = self.cal_best_paths(self.paths)
        
        self.build_mpls_forward_table()
        self.build_mpls_fec(self.best_paths)
        #self.build_meter_table()


    def pprint_topo(self):
        """
            Pretty print the topo. Debugging only.
        """
        for sw in self.switches:
            for neigh_city, attrs in sw.sw_links.items():
                logging.debug(f"{str(sw)}:{attrs['port']} -> {str(neigh_city)} port_mac: {attrs['mac']} weights: {self.weights[sw.city][neigh_city]}")
            logging.debug(f"{str(sw)}:{sw.host_port} -> {str(sw.host)}")

    def build_mpls_path(self, path: list):
        """
            The `path` is a list of City. This function convert it to a list of ports (MPLS labels)
        """
        mpls_ports = []

        for i in range(len(path) - 1):
            cur = path[i]
            next = path[i+1]

            cur_port, cur_mac, next_port, next_mac = self.switches[cur].get_link_to(next)

            mpls_ports.append(cur_port)

        return mpls_ports

    def build_mpls_fec(self, best_paths):
        """
            Build all MPLS routes based on the best_path
        """
        for sw1 in self.switches:
            c1 = sw1.city

            for i in range(16):
                if i != c1:
                    dst_sw = self.switches[i]
                    c2 = dst_sw.city

                    # 1 2 1 2 => 2 is on the bottom of the stack
                    self.build_mpls_from_to(c1, c2, best_paths[c1][c2])

    def build_mpls_from_to(self, c1: City, c2: City, path: list):
        """
            Build a single path from c1 to c2.

            Note this only build one-way path.
        """
        sw1 = self.switches[c1]
        sw2 = self.switches[c2]
        mpls_path = list(map(str, self.build_mpls_path(path)[::-1]))

        handle_1 = sw1.dst_table_add(c2, "FEC_tbl", f"mpls_ingress_{len(mpls_path)}_hop", [sw1.host.lpm, sw2.host.ip], mpls_path, path)

        # Add meters
        sw1.set_direct_meter_bandwidth('rate_limiting_meter', handle_1, 0.001, 0.001, 1600, 1600)

    def build_mpls_forward_table(self):
        """
            Build mpls_forward table.

            Note this function should be called exactly once.
        """
        for sw1 in self.switches:
            c1 = sw1.city

            sw1.table_add("FEC_tbl", "ipv4_forward", ["0.0.0.0/0", sw1.host.ip], [sw1.host.mac, str(sw1.host.sw_port)])
            
            for c2 in sw1.sw_links:
                c1_port, c1_mac, c2_port, c2_mac = sw1.get_link_to(c2)

                # maybe optimize??
                sw1.table_add("mpls_tbl", "mpls_forward", [ str(c1_port), "0" ], [c2_mac, str(c1_port)])
                sw1.table_add("lfa_mpls_tbl", "mpls_forward", [ str(c1_port), "0" ], [c2_mac, str(c1_port)])
                sw1.table_add("meter_mpls_tbl", "mpls_forward", [ str(c1_port), "0" ], [c2_mac, str(c1_port)])
                sw1.table_add("mpls_tbl", "penultimate", [ str(c1_port), "1" ], [c2_mac, str(c1_port)])
                sw1.table_add("lfa_mpls_tbl", "penultimate", [ str(c1_port), "1" ], [c2_mac, str(c1_port)])
                sw1.table_add("meter_mpls_tbl", "penultimate", [ str(c1_port), "1" ], [c2_mac, str(c1_port)])

    def fullfil_link_capcaity(self, path: tuple, req: int):
        """
            Check if the path fullfills the capacity.
        """
        for i in range(len(path)-1):
            c1 = path[i]
            c2 = path[i+1]
            if self.links_capacity[c1][c2] < req:
                return False
        
        return True
    
    def sub_link_capacity(self, c1: City, c2: City, val: int):
        """
            Substract the capacity for the given link.
        """
        self.links_capacity[c1][c2] -= val
        self.links_capacity[c2][c1] -= val
    
    def sub_path_link_capcity(self, path: tuple, val):
        """
            Substract the capacity for the given path.
        """
        for i in range(len(path)-1):
            c1 = path[i]
            c2 = path[i+1]
            self.sub_link_capacity(c1, c2, val)
    
    def sub_path_if_fullfilled(self, path: tuple, req: int):
        """
            If the path fullfill the capacity request, substract the capacity for the given link.
        """
        if self.fullfil_link_capcaity(path, req):
            self.sub_path_link_capcity(path, req)
            return True
        else:
            return False

    def parse_speed(self, spd: str):
        """
            Convert the speed string to int.

            1mbps -> 1e6
            1kbps -> 1e3
        """
        spd = spd.lower()
        if spd.endswith("mbps"):
            pl = 1000000
        else:
            pl = 1000
        
        spd_num = ""
        for c in spd:
            if c in ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]:
                spd_num += c
            else:
                break
        
        return int(spd_num) * pl

        
    def cal_best_paths(self, paths):
        """
            Select the best path from all available paths.
        """

        best_paths = [ [ () for j in range(16) ] for i in range(16) ]

        for sla in self.slas:
            if sla.type == "wp":
                try:
                    # Fullfill the waypoint sla.
                    target_city =  city_maps[sla.target]
                    src_city = self.parse_city_str(sla.src)[0]
                    dst_city = self.parse_city_str(sla.dst)[0]
                    self.wps[src_city][dst_city] = target_city
                    # TODO: Optimize by ports?
                    for p in paths[src_city][dst_city]:
                        if target_city in p[0]:
                            best_paths[src_city][dst_city] = p[0]
                            logging.debug(f"Select the best path based on sla {str(src_city)} -> {str(target_city)} -> {str(dst_city)}: {p[0]}")
                            break
                except (KeyError, IndexError):
                    logging.exception("")

        # Try to do reservation.
        for fl in self.flows:
            c1 = self.parse_city_str(fl['src'])[0]
            c2 = self.parse_city_str(fl['dst'])[0]
            if best_paths[c1][c2] == ():
                if fl['protocol'] == 'udp':
                    rt = self.parse_speed(fl['rate'])
                else:
                    rt = self.parse_speed(fl['size'])
                all_paths_with_weights = paths[c1][c2]

                for ps, _ in all_paths_with_weights:
                    if self.sub_path_if_fullfilled(ps, rt):
                        best_paths[c1][c2] = ps
                        break
        
        # Try to make full use of all links.
        for i in range(16):
            for j in range(16):
                if i < j:
                    c1 = City(i)
                    c2 = City(j)
                    if best_paths[c1][c2] == ():
                        all_paths_with_weights = paths[c1][c2]

                        for ps, _ in all_paths_with_weights:
                            if self.sub_path_if_fullfilled(ps, 1e7):
                                best_paths[c1][c2] = ps
                                break
        
        # If we can't find a best path, use the path with the smallest weight.
        return [ [ paths[i][j][0][0] if best_paths[i][j] == () and len(paths[i][j]) != 0  else best_paths[i][j] for j in range(16) ] for i in range(16) ]

    def cal_paths(self):
        """
            Calculate all possible paths with BFS and Floyd alogrithm.

            This function is super slow, be cautious.
        """
        dis = [ [ 0xFFFF for __ in range(16) ] for _ in range(16)]

        for city1, c1_w in self.weights.items():
            for city2, w in c1_w.items():
                dis[city1][city2] = w
        
        def _paths_from_city(src_city: City):
            ps = []
            ps.append( ((src_city,), 0) )
            idx = 0
            while idx < len(ps):
                top = ps[idx]
                idx += 1
                cur = top[0][-1]

                for j in range(16):
                    if dis[cur][j] != 0xFFFF and j not in top[0]:
                        ps.append( (top[0] + (City(j),), top[1] + dis[cur][j]) )
            
            return ps

        paths = [ [ [] for __ in range(16) ] for _ in range(16)]
        for i in range(16):
            ps = _paths_from_city(City(i))

            for p in ps:
                dst = p[0][-1]
                w = p[1]
                if w > 0:
                    paths[i][dst].append(p)

        for i in range(16):
            for j in range(16):
                paths[i][j].sort(key=lambda t: t[1])
        
        return paths

    def reset_states(self):
        """Resets switches state"""
        [controller.reset_state() for controller in self.controllers.values()]

    def build_topo(self):
        """
            Build the topo we prefer.
        """
        intfs = self.topo.get_node_intfs()

        for sw in self.switches:
            city = sw.city
            city_name = str(city)

            host_name = f"{city_name}_h0"
            city_intfs = intfs[city_name]
            host_intfs = intfs[host_name]

            sw.controller = self.controllers[city]

            for _, attrs in host_intfs.items():
                if attrs['node_neigh'] == str(sw):
                    sw.host.lpm = attrs['ip']
                    sw.host.mac = attrs['addr']
                    sw.host.sw_port = attrs['port_neigh']
                    sw.host.sw_interface = attrs['intfName_neigh']

            for _, attrs in city_intfs.items():
                if "delay" in attrs and attrs['node'] == city_name:
                    neigh_city = city_maps[attrs['node_neigh']]
                    neigh_switch = self.switches[neigh_city]
                    bw = float(int(attrs['bw']))
                    sw.sw_links[neigh_city] = {
                        "port" : attrs['port'], # TODO: Tuple?
                        "delay" : attrs['delay'],
                        "mac" : attrs['addr'],
                        "sw" : neigh_switch,
                        "bw" : bw,
                        "interfaces" : (attrs['intfName'], attrs['intfName_neigh'])
                    }

                    sw.sw_ports[attrs['port']] = neigh_switch
                    # Calculate weights by delay
                    self.weights[city][neigh_city] = float(attrs['delay'][:-2])
                    self.weights[neigh_city][city] = float(attrs['delay'][:-2])
                    # Update the link capacity
                    self.links_capacity[city][neigh_city] = 1e7
                    self.links_capacity[neigh_city][city] = 1e7
        
        self.initial_weights = copy.deepcopy(self.weights)
        self.pprint_topo()

    def connect_to_switches(self):
        """Connects to switches"""
        for p4switch in self.topo.get_p4switches():
            thrift_port = self.topo.get_thrift_port(p4switch)
            self.controllers[city_maps[p4switch]] = SimpleSwitchThriftAPI(thrift_port)
            logging.debug(f"Switch: {p4switch} port: {thrift_port}")
    
    def sanity_check(self):
        """
            Sanity check for weights.
        """
        for city1, city_weights in self.weights.items():
            for city2, w in city_weights.items():
                if city1 in self.weights[city2] and self.weights[city2][city1] != w:
                    logging.warning(f"Mismatched weights between {city1} and {city2}!")
                
                if city1 not in self.weights[city2]:
                    logging.warning(f"Reverse weight doesn't exist for {city2} -> {city1}, setting it to {w}")
                    self.weights[city2][city1] = w

    def mpls_path_rebuild(self, path):
        mpls_ports = []

        for i in range(len(path) - 1):
            cur = path[i]
            next = path[i + 1]
            cur_port, cur_mac, next_port, next_mac = self.switches[cur].get_link_to(next)
            mpls_ports.append(cur_port)

        return mpls_ports

    def path_valid(self, path, sw1: Switch):
        for i in range(len(sw1.failed_link)):
            if sw1.failed_link[i] in path:
                return False
        return True

    def path_direct_valid(self, path, sw1: Switch):
        for i in range(len(sw1.failed_link) - 1):
            if sw1.failed_link[i] in path:
                return False
        return True

    def build_meter_alt_paths(self, src: City, dst: City):
        """
            Build the alternative paths based on the result of cal_paths()
        """
        all_possible_paths = self.paths[src][dst]
        alternative_paths = []
        logging.debug(f"[Meter-Table] All possible links between {str(src)} -> {str(dst)}")
        logging.debug(f"[Meter-Table]  {all_possible_paths}")
        for path, weight in all_possible_paths:
            s = self.links_capacity[path[0]][path[1]] # Record the link capacity
            for i in range(len(path) - 1):
                if self.links_capacity[path[i]][path[i+1]] < s:
                    s = self.links_capacity[path[i]][path[i+1]]
            
            alternative_paths.append((path, s))
        logging.debug(f"[Meter-Table]  Alternative path \n{alternative_paths}")
        alternative_paths.sort(key=lambda tp: tp[1])
        if (alternative_paths[0][0] != self.best_paths[src][dst]):
            return alternative_paths[0][0]
        else:
            return None

    def build_meter_table(self):
        for sw1 in self.switches:
            c1 = sw1.city

            for i in range(16):
                if i != c1:
                    dst_sw = self.switches[i]
                    logging.debug(f"[Meter-Table] build alt Link between {str(sw1.city)} -> {str(dst_sw.city)}")
                    c2 = dst_sw.city
                    alt_path = self.build_meter_alt_paths(c1, c2)
                    if (alt_path != None):
                        logging.debug(f"[Meter-Table] Use Path {alt_path}")
                        mpls_path = list(map(str, self.build_mpls_path(alt_path)[::-1]))
                        sw1.dst_table_add(c2, "meter_table", f"lfa_replace_{len(mpls_path)}_hop", [sw1.host.lpm, dst_sw.host.ip], mpls_path, alt_path)
            

    def build_failure_rerout(self, sw1_wf: Switch, sw2_wf: Switch):
        """ Reroute the traffic when failures are detected
        """
        sw_l = []
        sw_l.append(sw1_wf)
        sw_l.append(sw2_wf)

        # Add the failed link to sw.failed_link
        sw1_wf.failed_link.append(sw2_wf.city)
        sw2_wf.failed_link.append(sw1_wf.city)

        logging.debug(f"[Failure-Recover] Link between {str(sw1_wf.city)} -> {str(sw2_wf.city)} failed")
        logging.debug(f"[Failure-Recover] Recompute routing paths")
        
        # Rebuild all routes avoiding the failed link
        for i in range(2):
            for j in range(16):
                if(j != sw_l[i].city):
                    # Check whether from swi_wf.city to j uses the failed link
                    if(sw_l[1-i].city in self.best_paths[sw_l[i].city][j]):
                        logging.debug(f"[Failure-Recover] {str(sw_l[1-i].city)} in {self.best_paths[sw_l[i].city][j]}")
                        # Find the first route with out the failed link
                        logging.debug(f"[Failure-Recover] failed_link of {str(sw_l[1-i].city)} : {sw_l[1-i].failed_link}")
                        for p in self.paths[sw_l[i].city][j]:
                            # Check the direct connect link
                            if (sw_l[1-i].city == p[0][-1]):
                                if self.path_direct_valid(p[0], sw_l[i]):
                                    # The failed link is directly connected to the destination
                                    dst_sw = self.switches[j]
                                    # Add dst ip to sw.in_reroute_table
                                    if dst_sw.host.ip in sw_l[i].in_reroute_table:
                                        # If the dst is already in the table
                                        mpls_path = list(map(str, self.mpls_path_rebuild(p[0])[::-1]))
                                        handle_1 = sw_l[i].table_modify("LFA_REP_tbl", sw_l[i].in_reroute_table[dst_sw.host.ip], f"lfa_replace_{len(p[0]) - 1}_hop", mpls_path)
                                        # Store the handle of the table
                                        sw_l[i].in_reroute_table[dst_sw.host.ip] = handle_1
                                        action_name = f"lfa_replace_{len(p[0]) - 1}_hop"
                                        match_keys = [dst_sw.host.ip]
                                        logging.debug(f"[Failure-Recover] [{str(sw_l[i].city)}] -> [{str(dst_sw.city)}] Path Change table_modify LFA_REP_tbl {action_name} {match_keys} {mpls_path}")
                                        break
                                    else:
                                        mpls_path = list(map(str, self.mpls_path_rebuild(p[0])[::-1]))
                                        handle_1 = sw_l[i].table_add("LFA_REP_tbl", f"lfa_replace_{len(p[0]) - 1}_hop", [dst_sw.host.ip], mpls_path)
                                        sw_l[i].in_reroute_table[dst_sw.host.ip] = handle_1
                                        action_name = f"lfa_replace_{len(p[0]) - 1}_hop"
                                        match_keys = [dst_sw.host.ip]
                                        logging.debug(f"[Failure-Recover] [{str(sw_l[i].city)}] -> [{str(dst_sw.city)}] Path Change table_add LFA_REP_tbl {action_name} {match_keys} {mpls_path}")
                                        break
                            
                            # Check the validity of the path
                            if self.path_valid(p[0], sw_l[i]):
                                dst_sw = self.switches[j]
                                # Add dst ip to sw.in_reroute_table
                                if dst_sw.host.ip in sw_l[i].in_reroute_table:
                                    # If the dst is already in the table
                                    mpls_path = list(map(str, self.mpls_path_rebuild(p[0])[::-1]))
                                    handle_1 = sw_l[i].table_modify("LFA_REP_tbl", sw_l[i].in_reroute_table[dst_sw.host.ip], f"lfa_replace_{len(p[0]) - 1}_hop", mpls_path)
                                    # Store the handle of the table
                                    sw_l[i].in_reroute_table[dst_sw.host.ip] = handle_1
                                    action_name = f"lfa_replace_{len(p[0]) - 1}_hop"
                                    match_keys = [dst_sw.host.ip]
                                    logging.debug(f"[Failure-Recover] [{str(sw_l[i].city)}] -> [{str(dst_sw.city)}] Path Change table_modify LFA_REP_tbl {action_name} {match_keys} {mpls_path}")
                                    break
                                else:
                                    mpls_path = list(map(str, self.mpls_path_rebuild(p[0])[::-1]))
                                    handle_1 = sw_l[i].table_add("LFA_REP_tbl", f"lfa_replace_{len(p[0]) - 1}_hop", [dst_sw.host.ip], mpls_path)
                                    sw_l[i].in_reroute_table[dst_sw.host.ip] = handle_1
                                    action_name = f"lfa_replace_{len(p[0]) - 1}_hop"
                                    match_keys = [dst_sw.host.ip]
                                    logging.debug(f"[Failure-Recover] [{str(sw_l[i].city)}] -> [{str(dst_sw.city)}] Path Change table_add LFA_REP_tbl {action_name} {match_keys} {mpls_path}")
                                    break
                    # Match with ipv4_forward 
                    # else:
                        # Keep the original route
                        # path = self.best_paths[sw_l[i].city][j]
                        # dst_sw = self.switches[j]
                        # mpls_path = list(map(str, self.mpls_path_rebuild(path)[::-1]))
                        # sw_l[i].table_add("LFA_REP_tbl", f"lfa_replace_{len(path) - 1}_hop", [dst_sw.host.ip], mpls_path)
                        # action_name = f"lfa_replace_{len(path) - 1}_hop"
                        # match_keys = [str(dst_sw.host.ip)]
                        # logging.debug(f"[Failure-Recover] [{str(sw_l[i].city)}] -> [{str(dst_sw.city)}] Path remains, table_add LFA_REP_tbl {action_name} {match_keys} {mpls_path}")



    def has_failure(self, pong: Pong, ports: list):
        sw2 = pong.sw

        logging.debug(f"[{str(sw2)}]: Possible failures from {ports}")
        for port in ports:
            sw1 = sw2.sw_ports[port] # type: Switch

            if self.weights[sw1.city][sw2.city] != 0xFFFF:
                logging.debug(f"Get a failure from {str(sw1)} -> {str(sw2)} weights {self.weights[sw1.city][sw2.city]} {self.weights[sw2.city][sw1.city]}")
                self.weights[sw1.city][sw2.city] = 0xFFFF
                self.weights[sw2.city][sw1.city] = 0xFFFF
                
                # self.build_failure_rerout(sw2, sw1)
                # Set register
                # sw_port_index_1 = sw1.sw_links[sw2.city]['port']
                # sw1.controller.register_write('linkState', sw_port_index_1, 1)
                # sw_port_index_2 = sw2.sw_links[sw1.city]['port']
                # sw2.controller.register_write('linkState', sw_port_index_2, 1)
                self.paths = self.cal_paths()
                self.best_paths = self.cal_best_paths(self.paths)
                self.build_mpls_fec(self.best_paths)
                #self.build_meter_table()

        

    def no_failure(self, pong: Pong, ports: list):
        sw2 = pong.sw

        for port in ports:
            sw1 = sw2.sw_ports[port] # type: Switch
            if self.weights[sw1.city][sw2.city] != 0xFFFF:
                continue
            
            logging.debug(f"Failure recovery from {str(sw1)} -> {str(sw2)} weights {self.weights[sw1.city][sw2.city]} {self.weights[sw2.city][sw1.city]}")
            self.weights[sw1.city][sw2.city] = self.initial_weights[sw1.city][sw2.city]
            self.weights[sw2.city][sw1.city] = self.initial_weights[sw2.city][sw1.city]
            # Set back register
            # sw_port_index_1 = sw1.sw_links[sw2.city]['port']
            # sw1.controller.register_write('linkState', sw_port_index_1, 0)
            # sw_port_index_2 = sw2.sw_links[sw1.city]['port']
            # sw2.controller.register_write('linkState', sw_port_index_2, 0)
            # Update sw.failed_link list
            # sw1.failed_link.remove(sw2.city)
            # sw2.failed_link.remove(sw1.city)
            self.paths = self.cal_paths()
            self.best_paths = self.cal_best_paths(self.paths)
            self.build_mpls_fec(self.best_paths)
            #self.build_meter_table()


    def rt_flows(self, monitor: FlowMonitor, flows: dict, interval: float):
        """
            This function is called periodically to check if we have to reroute.

            IMPORTANT: Sometimes this function is too slow to catch up with the real time flow.
        """
        def sub_cur_link_by_path(cur_links: list, path: list, spd: float):
            for i in range(len(path) - 1):
                cur_links[path[i]][path[i+1]] -= spd

        def cal_average_capcacity(path: list, cur_links: list):
            s = 0
            for i in range(len(path) - 1):
                s += cur_links[path[i]][path[i+1]]

            return s / (len(path) - 1)

        cur_links = [ [ 0 for _ in range(16) ] for _ in range(16)]

        for c1 in self.weights:
            for c2 in self.weights[c1]:
                cur_links[c1][c2] = 1e7
                cur_links[c2][c1] = 1e7

        cur_links_map = [ [ [] for _ in range(16) ] for _ in range(16)]
        for src, fls in flows.items():
            for fl, spd in fls.items():
                c1, _, c2, _, _ = fl
                spd = (spd / interval) * 8
                if c2 == src : # Make sure the flow is not dropped  
                    sub_cur_link_by_path(cur_links, self.best_paths[c1][c2], spd)

        
        for src, fls in flows.items():
            for fl, spd in fls.items():
                c1, _, c2, _, _ = fl
                spd = (spd / interval) * 8
                if c2 == src : # Make sure the flow is not dropped  
                    if self.wps[c1][c2] is None:
                        # Restore current links status and then make decision
                        sub_cur_link_by_path(cur_links, self.best_paths[c1][c2], -spd)
                        cur_average_capa = cal_average_capcacity(self.best_paths[c1][c2], cur_links)
                        for p, _ in self.paths[c1][c2]:
                            aver = cal_average_capcacity(p, cur_links)
                            # If we find a route with more capcacity.
                            if cur_average_capa <= 7 * 1e6 and ( aver > cur_average_capa or aver >= 9 * 1e6 ):
                                # Do reroute
                                logging.debug(f"Reroute from {self.best_paths[c1][c2]} to {p} for cur={cur_average_capa} new={aver}")
                                self.best_paths[c1][c2] = p
                                self.build_mpls_from_to(c1, c2, p)
                                break
                        # Then update the links status.
                        sub_cur_link_by_path(cur_links, self.best_paths[c1][c2], spd)

    def start_monitor(self):
        """
            This function starts all monitors
        """
        ts = []
        #ts.append(LinkMonitor(self.rt_speed, 0.5))
        ts.append(FlowMonitor(self.switches, self.rt_flows, 0.5))

        for i in range(16):
            c1 = City(i)
            s1 = self.switches[c1]

            for c2 in s1.sw_links:
                s2 = self.switches[c2]

                if c1 < c2:
                    ts.append(Ping(s1, s2, 0.3))
                    ts.append(Ping(s2, s1, 0.3))
                    pass
        
        for i in range(16):
            ts.append(Pong(self.switches[i], 0.8, self.has_failure, self.no_failure))
        
        for t in ts:
            t.start()

        return ts

    def run(self):
        # Start all monitors and wait.
        monitors = self.start_monitor()

        for m in monitors:
            m.join()

    def main(self):
        """Main function"""
        self.run()


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--base-traffic', help='Path to scenario.base-traffic',
                        type=str, required=False, default='')
    parser.add_argument('--slas', help='SLA',
    type=str, required=False, default='')
    return parser.parse_args()


if __name__ == "__main__":
    args = get_args()
    try:
        controller = Controller(args.base_traffic, args.slas)
        controller.main()
    except KeyboardInterrupt:
        exit(0)
    except Exception as e:
        logging.exception("")
