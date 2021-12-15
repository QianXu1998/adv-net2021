"""Template of an empty global controller"""
import argparse
import csv
from os import path
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
from datetime import datetime
from thrift.Thrift import TApplicationException
import copy
# TODO: remove logging to speedup
logging.basicConfig(filename='/tmp/controller.log', format="[%(levelname)s] %(message)s", level=logging.DEBUG)
#logging.basicConfig(format="[%(levelname)s] %(message)s", level=logging.ERROR)
# [DEBUG] Switch: AMS
# [DEBUG] Switch: BAR
# [DEBUG] Switch: BER
# [DEBUG] Switch: BRI
# [DEBUG] Switch: EIN
# [DEBUG] Switch: FRA
# [DEBUG] Switch: GLO
# [DEBUG] Switch: LIL
# [DEBUG] Switch: LIS
# [DEBUG] Switch: LON
# [DEBUG] Switch: MAD
# [DEBUG] Switch: MAN
# [DEBUG] Switch: MUN
# [DEBUG] Switch: PAR
# [DEBUG] Switch: POR
# [DEBUG] Switch: REN

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

class Switch:

    def __init__(self, city: City):
        self.city = city
        self.sw_links = {}
        self.sw_ports = {}
        self.host = Host(self)
        self.controller = None # type: SimpleSwitchThriftAPI
        self.hosts_path = [ ( (), 0xFFFF ) for i in range(16) ]

    def get_link_to(self, city: City):
        #logging.debug(self.sw_links)
        next_sw = self.sw_links[city]['sw']
        return self.sw_links[city]['port'], self.sw_links[city]['mac'], next_sw.sw_links[self.city]['port'], next_sw.sw_links[self.city]['mac']

    def table_add(self, table_name, action_name, match_keys, action_params, prio=0):
        r = self.controller.table_add(table_name, action_name, match_keys, action_params, prio)
        logging.debug(f"[{str(self)}] table_add {table_name} {action_name} {match_keys} {action_params} {prio} ret={r}")
        if r is None:
            logging.warning(f"[{str(self)}] table_add ret is None!")
        return r

    def table_modify(self, table_name, hdl, action_name, action_params):
        r = self.controller.table_modify(table_name, action_name, hdl, action_params)
        logging.debug(f"[{str(self)}] table_modify {table_name} {action_name} {action_params} hdl={hdl} ret={r}")
        return r

    def dst_table_add(self, dst: City, table_name, action_name, match_keys, action_params, best_path):
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

    @property
    def host_port(self):
        return self.host.sw_port

    def __str__(self):
        return str(self.city)

class Host:
    def __init__(self, sw: Switch):
        self.city_sw = sw
        self.mac = None
        self._lpm = None
        self._ip = None
        self.sw_port = None
    
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

class Nop(threading.Thread):
    """
        Detect a link failure , send a packet to the controller to update it
    """

    def __init__(self, port_index, port_state, sw1: Switch, sw2: Switch):
        super().__init__()
        self.sw1 = sw1
        self.sw2 = sw2
        self.port_index = port_index
        self.port_state = port_state
    
    def build_link_state_1(self):
        s1_port, s1_mac, s2_port, s2_mac = self.sw1.get_link_to(self.sw2.city)
        bs = b""
        bs += b"".join(map(binascii.unhexlify, s2_mac.split(":")))
        bs += b"".join(map(binascii.unhexlify, s1_mac.split(":")))
        bs += struct.pack(">H", 0x2020)
        bs += struct.pack(">H", (self.port_index << 9) | (self.port_state << 8))

        return bs
    
    def build_link_state_2(self):
        s1_port, s1_mac, s2_port, s2_mac = self.sw1.get_link_to(self.sw2.city)
        bs = b""
        bs += b"".join(map(binascii.unhexlify, s1_mac.split(":")))
        bs += b"".join(map(binascii.unhexlify, s2_mac.split(":")))
        bs += struct.pack(">H", 0x2020)
        bs += struct.pack(">H", (self.port_index << 1) | (self.port_state))

        return bs

    def run(self):
        inf1, inf2 = self.sw1.sw_links[self.sw2.city]['interfaces']

        logging.debug(f"[NOP-MESSAGE] [{str(self.sw1)}] Sent Link failed packet to {inf1}")
        skt = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        skt.bind((inf1, 0))
        bs = self.build_link_state_1()
        logging.debug(f"[NOP-MESSAGE] [{str(self.sw1)}] -> [{str(self.sw2)}]: Sniffing {inf1}")
        try:
            skt.send(bs)
            logging.debug(f"[NOP-MESSAGE] [{str(self.sw1)}] Sent packet to {inf1}")
        except OSError:
            skt.close()


class Ping(threading.Thread):

    def __init__(self, sw1: Switch, sw2: Switch, interval: float):
        super().__init__()
        # sw1 < sw2!
        self.sw1 = sw1
        self.sw2 = sw2
        self.interval = interval

    def build_hearbeat(self):
        s1_port, s1_mac, _, s2_mac = self.sw1.get_link_to(self.sw2.city)
        bs = b""
        bs += b"".join(map(binascii.unhexlify, s2_mac.split(":")))
        bs += b"".join(map(binascii.unhexlify, s1_mac.split(":")))
        bs += struct.pack(">H", 0x1926)
        bs += struct.pack(">H", (s1_port << 7) | (1 << 6))

        return bs


    def run(self):
        try:
            inf1, inf2 = self.sw1.sw_links[self.sw2.city]['interfaces']

            while True:
                skt = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)

                skt.bind((inf1, 0))
                bs = self.build_hearbeat()
                logging.debug(f"[{str(self.sw1)}] -> [{str(self.sw2)}]: Sniffing {inf1}")
                while True:
                    try:
                        skt.send(bs)
                        #logging.debug(f"[{str(self.sw1)}] Sent packet to {inf1}")
                        time.sleep(self.interval)
                    except OSError:
                        skt.close()
                        time.sleep(self.interval)
                        break
        except KeyboardInterrupt:
            return
        except Exception:
            logging.exception("")


class Pong(threading.Thread):

    def __init__(self, sw: Switch, threshold: float, failure_cb: callable, good_cb: callable):
        super().__init__()
        # sw1 < sw2!
        self.sw = sw
        self.failure_cb = failure_cb
        self.good_cb = good_cb
        self.threshold = threshold
        self.last_seen = {}
        self.latest_timestamp = 0

        for p in self.sw.sw_ports:
            self.last_seen[p] = None
    
    def unpack_digest(self, msg: bytes, num_samples: int):
        digest = []
        starting_index = 32
        for _ in range(num_samples):
            #logging.debug(f"[{str(self.sw)}]: msg={msg[starting_index:starting_index+8]}")
            stamp0, stamp1, port = struct.unpack(">LHH", msg[starting_index:starting_index+8])
            starting_index +=8
            stamp = (stamp0 << 16) + stamp1
            digest.append( (port, stamp / 1e6) )
        return digest

    def process_stamps(self, stamps: list):
        #logging.debug(f"[{str(self.sw)}] Get stamps={stamps}")
        for port, stamp in stamps:
            if stamp > self.latest_timestamp:
                self.latest_timestamp = stamp
            if self.last_seen[port] is None:
                self.last_seen[port] = stamp
                continue
            else: 
                d = stamp - self.last_seen[port]
                #logging.debug(f"[{str(self.sw)}]: d={d} port={port} stamp={stamp}")
                if d > self.threshold :
                    pass
                    #self.failure_cb(self, [port])
                else:
                    self.good_cb(self, [port])

                self.last_seen[port] = stamp

    def process(self, msg: bytes):
        topic, device_id, ctx_id, list_id, buffer_id, num = struct.unpack("<iQiiQi",
                                                                          msg[:32])
        digest = self.unpack_digest(msg, num)
        self.process_stamps(digest)
        #Acknowledge digest
        self.sw.controller.client.bm_learning_ack_buffer(ctx_id, list_id, buffer_id)

    def run(self):
        try:
            skt = nnpy.Socket(nnpy.AF_SP, nnpy.SUB)
            #time.sleep(5)
            #self.sw2.controller.mirroring_add
            ns = self.sw.controller.client.bm_mgmt_get_info().notifications_socket
            logging.debug(f"[{str(self.sw)}]: ns={ns} threshold={self.threshold}")
            skt.connect(ns)
            skt.setsockopt(nnpy.SUB, nnpy.SUB_SUBSCRIBE, '')
            while True:
                #logging.debug(f"in while")
                try:
                    #logging.debug(f"[{str(self.sw)}]: seen={self.last_seen} latest={self.latest_timestamp}")
                    time.sleep(self.threshold)
                    msg = skt.recv(nnpy.DONTWAIT)
                    #logging.debug(f"[{str(self.sw)}] recv {msg}")
                    self.process(msg)
                except AssertionError:
                    # fports = []
                    # for p in self.sw.sw_ports:
                    #     if self.last_seen[p] is not None:
                    #         n = datetime.now()
                    #         if n.timestamp() - self.last_seen[p] > self.threshold:
                    #             fports.append(p)
                    
                    # if len(fports) != 0:
                    #     self.failure_cb(self, fports)
                    #logging.debug(f"[{str(self.sw)}]")
                    #logging.exception("")
                    pass
                except TApplicationException:
                    #logging.debug(f"[{str(self.sw)}]")
                    #logging.exception("")
                    pass
                finally:
                    fports = []
                    #logging.debug(f"[{str(self.sw)}] final")
                    if self.latest_timestamp != 0:
                        for p in self.sw.sw_ports:
                            if self.last_seen[p] is not None:
                                if self.latest_timestamp - self.last_seen[p] > self.threshold:
                                    fports.append(p)
                    
                    if len(fports) != 0:
                        self.failure_cb(self, fports)
                    
                    #logging.debug(f"[{str(self.sw)}] final done")
        except KeyboardInterrupt:
            return
        except Exception:
            logging.exception("")


class Controller(object):

    def __init__(self, base_traffic, slas):
        self.base_traffic_file = base_traffic
        self.slas_file = slas
        self.topo = load_topo('topology.json')
        self.controllers = {}
        self.links_capacity = [ [0 for __ in range(16)] for _ in range(16) ]
        #self.weights = copy.deepcopy(initial_weights)
        self.weights = { City(i) : {} for i in range(16) }
        self.switches = [Switch(City(i)) for i in range(16)]
        self.all_available_path = []
        self.thrift_controller = None
        self.init()

    def parse_inputs(self):
        with open(self.slas_file, "r+") as f:
            rdr = csv.DictReader(cleanfile(f))
            self.slas = [make_sla(spec) for spec in rdr]
        self.flows = parse_traffic(self.base_traffic_file)

    def parse_city_str(self, s: str):
        if s is None:
            return [City(i) for i in range(16)]
        return [city_maps[s.split("_")[0]]]

    def parse_port_range(self, tp: tuple):
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

    def allow_sla_flows(self):
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

            for src_city in src_cities:
                sw1 = self.switches[src_city] # type: Switch
                
                for dst_city in dst_cities:
                    if src_city != dst_city:
                        sw2 = self.switches[dst_city] # type: Switch

                        sw1.table_add(tname, "NoAction", [str(sw1.host.sw_port), sw2.host.lpm, f"{src_l}->{src_r}", f"{dst_l}->{dst_r}"], [], 1 + int(dst_city) + sla_idx * len(self.slas))
                        sw2.table_add(tname, "NoAction", [str(sw2.host.sw_port), sw1.host.lpm, f"{dst_l}->{dst_r}", f"{src_l}->{src_r}"], [], 1 + int(dst_city) + sla_idx * len(self.slas))

                for p in sw1.sw_ports.keys():
                    sw1.table_add("tcp_sla", "NoAction", [str(p), "0.0.0.0/0", "0->65535", "0->65535"], [], 0)
                    sw1.table_add("udp_sla", "NoAction", [str(p), "0.0.0.0/0", "0->65535", "0->65535"], [], 0)

    
    def init(self):
        """Basic initialization. Connects to switches and resets state."""
        self.connect_to_switches()
        self.reset_states()
        self.build_topo()
        self.sanity_check()
        self.parse_inputs()
        self.allow_sla_flows()

        # Test thrift_api
        # self.thrift_controller = ThriftAPI(9100, "10.0.11.1/24", "none")

        # TODO: Build shortest paths by bw requests
        #self.paths = self.cal_paths()
        #self.shortest_paths = self.cal_shortest_path()
        self.best_paths = self.cal_best_paths()
        
        self.build_mpls_forward_table()
        self.build_mpls_fec()

        
        # import ipdb

        # ipdb.set_trace()


    def pprint_topo(self):
        for sw in self.switches:
            for neigh_city, attrs in sw.sw_links.items():
                logging.debug(f"{str(sw)}:{attrs['port']} -> {str(neigh_city)} port_mac: {attrs['mac']}")
            logging.debug(f"{str(sw)}:{sw.host_port} -> {str(sw.host)}")

    def build_mpls_path(self, c1: City, c2: City):
        paths = self.best_paths[c1][c2]
        mpls_ports = []

        # TODO: Handle invalid paths!
        #logging.debug(f"Building mpls path for {str(c1)}->{str(c2)}: {paths}")
        for i in range(len(paths) - 1):
            cur = paths[i]
            next = paths[i+1]

            cur_port, cur_mac, next_port, next_mac = self.switches[cur].get_link_to(next)

            mpls_ports.append(cur_port)

        return mpls_ports

    def build_mpls_fec(self):
        for sw1 in self.switches:
            c1 = sw1.city

            for i in range(16):
                if i != c1:
                    dst_sw = self.switches[i]
                    c2 = dst_sw.city
                    # 1 2 1 2 => 2 is on the bottom of the stack
                    mpls_path = list(map(str, self.build_mpls_path(c1, c2)[::-1]))

                    # TODO: Fix sw1.host.lpm!!!!!!!!
                    sw1.dst_table_add(c2, "FEC_tbl", f"mpls_ingress_{len(mpls_path)}_hop", [sw1.host.lpm, dst_sw.host.ip], mpls_path, self.best_paths[c1][c2])


    def build_mpls_forward_table(self):
        for sw1 in self.switches:
            c1 = sw1.city

            sw1.table_add("FEC_tbl", "ipv4_forward", ["0.0.0.0/0", sw1.host.ip], [sw1.host.mac, str(sw1.host.sw_port)])
            # sw1.table_add("LFA_REP_tbl", "ipv4_forward", ["0.0.0.0/0", sw1.host.ip], [sw1.host.mac, str(sw1.host.sw_port)])

            
            for c2 in sw1.sw_links:
                c1_port, c1_mac, c2_port, c2_mac = sw1.get_link_to(c2)

                # maybe optimize??
                sw1.table_add("mpls_tbl", "mpls_forward", [ str(c1_port), "0" ], [c2_mac, str(c1_port)])
                sw1.table_add("lfa_mpls_tbl", "mpls_forward", [ str(c1_port), "0" ], [c2_mac, str(c1_port)])
                sw1.table_add("mpls_tbl", "penultimate", [ str(c1_port), "1" ], [c2_mac, str(c1_port)])
                sw1.table_add("lfa_mpls_tbl", "penultimate", [ str(c1_port), "1" ], [c2_mac, str(c1_port)])

    def fullfil_link_capcaity(self, path: tuple, req: int):
        for i in range(len(path)-1):
            c1 = path[i]
            c2 = path[i+1]
            if self.links_capacity[c1][c2] < req:
                return False
        
        return True
    
    def sub_link_capacity(self, c1: City, c2: City, val: int):
        self.links_capacity[c1][c2] -= val
        self.links_capacity[c2][c1] -= val
    
    def sub_path_link_capcity(self, path: tuple, val):
        for i in range(len(path)-1):
            c1 = path[i]
            c2 = path[i+1]
            self.sub_link_capacity(c1, c2, val)
    
    def sub_path_if_fullfilled(self, path: tuple, req: int):
        if self.fullfil_link_capcaity(path, req):
            self.sub_path_link_capcity(path, req)
            return True
        else:
            return False

    def parse_speed(self, spd: str):
        spd = spd.lower()
        if spd.endswith("mbps"):
            pl = 1000
        else:
            pl = 1
        
        spd_num = ""
        for c in spd:
            if c in ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]:
                spd_num += c
            else:
                break
        
        return int(spd_num) * pl

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

    def set_direct_meter_bandwidth(self, meter_name, handle, bw_committed, bw_peak, burst_committed, burst_peak, sw: Switch):
        rates = self.get_meter_rates_from_bw(bw_committed, burst_committed, bw_peak, burst_peak)
        sw.controller.meter_set_rates(meter_name, handle, rates)
        
    def cal_best_paths(self):
        paths = self.cal_paths()

        self.all_available_path = copy.deepcopy(paths) # Saved the computed available paths

        best_paths = [ [ () for j in range(16) ] for i in range(16) ]

        for sla in self.slas:
            if sla.type == "wp":
                try:
                    target_city =  city_maps[sla.target]
                    src_city = self.parse_city_str(sla.src)[0]
                    dst_city = self.parse_city_str(sla.dst)[0]

                    # TODO: Optimize by ports?
                    for p in paths[src_city][dst_city]:
                        if target_city in p[0]:
                            best_paths[src_city][dst_city] = p[0]
                            logging.debug(f"Select the best path based on sla {str(src_city)} -> {str(target_city)} -> {str(dst_city)}: {p[0]}")
                            break
                except (KeyError, IndexError):
                    logging.exception("")

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
        
        for i in range(16):
            for j in range(16):
                if i < j:
                    c1 = City(i)
                    c2 = City(j)
                    if best_paths[c1][c2] == ():
                        all_paths_with_weights = paths[c1][c2]

                        for ps, _ in all_paths_with_weights:
                            if self.sub_path_if_fullfilled(ps, 10000):
                                best_paths[c1][c2] = ps
                                break

        return [ [ paths[i][j][0][0] if best_paths[i][j] == () and len(paths[i][j]) != 0  else best_paths[i][j] for j in range(16) ] for i in range(16) ]

    def cal_paths(self):
        dis = [ [ 0xFFFF for __ in range(16) ] for _ in range(16)]

        for city1, c1_w in self.weights.items():
            for city2, w in c1_w.items():
                dis[city1][city2] = w
        
        def _paths_from_city(src_city: City):
            ps = []
            ps.append( ((src_city,), 0) )
            idx = 0
            while idx < len(ps):
                #logging.debug(f"[{City(src_city)}]: ps={ps}")
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
                    #logging.debug(f"[{str(City(i))}] -> [{str(City(dst))}]: {p}")

        for i in range(16):
            for j in range(16):
                paths[i][j].sort(key=lambda t: t[1])
        
        return paths

    def reset_states(self):
        """Resets switches state"""
        [controller.reset_state() for controller in self.controllers.values()]

    def build_topo(self):
        logging.debug(f"{self.topo.get_node_intfs()}")

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
                    self.links_capacity[city][neigh_city] = bw
                    self.links_capacity[neigh_city][city] = bw
                    self.weights[city][neigh_city] = float(attrs['delay'][:-2])
                    self.weights[neigh_city][city] = float(attrs['delay'][:-2])
                    self.links_capacity[city][neigh_city] = 10000
                    self.links_capacity[neigh_city][city] = 10000
        
        self.initial_weights = copy.deepcopy(self.weights)
        self.pprint_topo()

    def connect_to_switches(self):
        """Connects to switches"""
        for p4switch in self.topo.get_p4switches():
            thrift_port = self.topo.get_thrift_port(p4switch)
            self.controllers[city_maps[p4switch]] = SimpleSwitchThriftAPI(thrift_port)
            logging.debug(f"Switch: {p4switch} port: {thrift_port}")
    
    def sanity_check(self):
        for city1, city_weights in self.weights.items():
            for city2, w in city_weights.items():
                if city1 in self.weights[city2] and self.weights[city2][city1] != w:
                    logging.warning(f"Mismatched weights between {city1} and {city2}!")
                
                if city1 not in self.weights[city2]:
                    logging.warning(f"Reverse weight doesn't exist for {city2} -> {city1}, setting it to {w}")
                    self.weights[city2][city1] = w

    # Nop Packet generating part
    def build_nop_packet(self, port_index, port_state, sw1: Switch, sw2: Switch):
        s1_port, s1_mac, s2_port, s2_mac = sw1.get_link_to(sw2.city)
        bs = b""
        bs += b"".join(map(binascii.unhexlify, s2_mac.split(":")))
        bs += b"".join(map(binascii.unhexlify, s1_mac.split(":")))
        bs += struct.pack(">H", 0x2020)
        bs += struct.pack(">H", (port_index << 9) | (port_state << 8))

        return bs

    def mpls_path_rebuild(self, path):
        mpls_ports = []

        for i in range(len(path) - 1):
            cur = path[i]
            next = path[i + 1]
            cur_port, cur_mac, next_port, next_mac = self.switches[cur].get_link_to(next)
            mpls_ports.append(cur_port)

        return mpls_ports

    def build_failure_rerout(self, sw1_wf: Switch, sw2_wf: Switch):
        """ Reroute the traffic when failures are detected
        """
        sw_l = []
        sw_l.append(sw1_wf)
        sw_l.append(sw2_wf)

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
                        for p in self.all_available_path[sw_l[i].city][j]:

                            if (sw_l[1-i].city == p[0][-1]):
                                # The failed link is directly connected to the destination
                                dst_sw = self.switches[j]
                                mpls_path = list(map(str, self.mpls_path_rebuild(self.all_available_path[sw_l[i].city][j][1][0])[::-1]))
                                sw_l[i].table_add("LFA_REP_tbl", f"lfa_replace_{len(mpls_path)}_hop", [dst_sw.host.ip], mpls_path)
                                action_name = f"lfa_replace_{len(mpls_path)}_hop"
                                match_keys = [dst_sw.host.ip]
                                logging.debug(f"[Failure-Recover] [{str(sw_l[i].city)}] -> [{str(dst_sw.city)}] Path Change table_add LFA_REP_tbl {action_name} {match_keys} {mpls_path}")
                                break

                            if sw_l[1-i].city not in p[0]:
                                dst_sw = self.switches[j]
                                mpls_path = list(map(str, self.mpls_path_rebuild(p[0])[::-1]))
                                sw_l[i].table_add("LFA_REP_tbl", f"lfa_replace_{len(p[0]) - 1}_hop", [dst_sw.host.ip], mpls_path)
                                action_name = f"lfa_replace_{len(p[0]) - 1}_hop"
                                match_keys = [dst_sw.host.ip]
                                logging.debug(f"[Failure-Recover] [{str(sw_l[i].city)}] -> [{str(dst_sw.city)}] Path Change table_add LFA_REP_tbl {action_name} {match_keys} {mpls_path}")
                                break
                    # else:
                        # Keep the original route
                        # path = self.best_paths[sw_l[i].city][j]
                        # dst_sw = self.switches[j]
                        # mpls_path = list(map(str, self.mpls_path_rebuild(path)[::-1]))
                        # sw_l[i].table_add("LFA_REP_tbl", f"lfa_replace_{len(path) - 1}_hop", [dst_sw.host.ip], mpls_path)
                        # action_name = f"lfa_replace_{len(path) - 1}_hop"
                        # match_keys = [str(dst_sw.host.ip)]
                        # logging.debug(f"[Failure-Recover] [{str(sw_l[i].city)}] -> [{str(dst_sw.city)}] Path remains, table_add LFA_REP_tbl {action_name} {match_keys} {mpls_path}")

    def send_link_update_message(self, sw1: Switch, sw2: Switch):
        failed_port_1, failed_port_2 = sw1.sw_links[sw2.city]['interfaces']
        port_index = sw1.sw_links[sw2.city]['port']
        packet = self.build_nop_packet(port_index, 1, sw1, sw2)

        for value in sw1.sw_links.values():
            try_port_1, try_port_2 = value['interfaces']
            logging.debug(f"[NOP-MESSAGE] [{str(sw1)}] Sent Link failed packet to {try_port_1}")
            skt = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            skt.bind((try_port_1, 0))
            logging.debug(f"[NOP-MESSAGE] [{str(sw1)}] -> [{str(sw2)}]: Sniffing {try_port_1}")
            try:
                skt.send(packet)
                break
            except OSError:
                skt.close()
                logging.debug(f"[NOP-MESSAGE] [{str(sw1)}] -> [{str(sw2)}]: Sending to {try_port_1} failed, try another one")

    def has_failure(self, pong: Pong, ports: list):
        sw2 = pong.sw

        logging.debug(f"[{str(sw2)}]: Possible failures from {ports}")
        for port in ports:
            sw1 = sw2.sw_ports[port] # type: Switch
            # sw2 hasn't receive hb for a long time!
            # TODO: Consider SLA??
            if self.weights[sw1.city][sw2.city] != 0xFFFF:
                logging.debug(f"Get a failure from {str(sw1)} -> {str(sw2)} weights {self.weights[sw1.city][sw2.city]} {self.weights[sw2.city][sw1.city]}")
                self.weights[sw1.city][sw2.city] = 0xFFFF
                self.weights[sw2.city][sw1.city] = 0xFFFF
                
                # sw_port_index = sw1.sw_links[sw2.city]['port']
                # sw1.controller.register_write('linkState', sw_port_index, 1)
                # sw_port_index = sw2.sw_links[sw1.city]['port']
                # sw2.controller.register_write('linkState', sw_port_index, 1)
                self.send_link_update_message(sw1, sw2)
                self.send_link_update_message(sw2, sw1)

                self.build_failure_rerout(sw2, sw1)
                register_read_value = sw2.controller.register_read('linkState')
                logging.debug(f"[REGISTER READ] linkState[{port} : {register_read_value}]")
                register_read_value = self.switches[City.PAR].controller.register_read('linkState')
                logging.debug(f"[REGISTER READ] {str(City.PAR)} : linkState[{register_read_value}]")
                # self.best_paths = self.cal_best_paths()
                # self.build_mpls_fec()

        

    def no_failure(self, pong: Pong, ports: list):
        sw2 = pong.sw

        #logging.debug(f"[{str(sw2)}]: Possible recovery from {ports}")
        for port in ports:
            sw1 = sw2.sw_ports[port] # type: Switch
            #logging.debug(f"[{str(sw2)}]: Recovery from {str(sw1)} -> {str(sw2)}")
            if self.weights[sw1.city][sw2.city] != 0xFFFF:
                return
            
            logging.debug(f"Failure recovery from {str(sw1)} -> {str(sw2)} weights {self.weights[sw1.city][sw2.city]} {self.weights[sw2.city][sw1.city]}")
            self.weights[sw1.city][sw2.city] = self.initial_weights[sw1.city][sw2.city]
            #logging.debug(f"2 Failure recovery from {str(sw1)} -> {str(sw2)} weights {self.weights[sw1.city][sw2.city]} {self.weights[sw2.city][sw1.city]} {initial_weights[sw1.city][sw2.city]} {initial_weights[sw2.city][sw1.city]}")
            self.weights[sw2.city][sw1.city] = self.initial_weights[sw2.city][sw1.city]
            #logging.debug(f"3 Failure recovery from {str(sw1)} -> {str(sw2)} weights {self.weights[sw1.city][sw2.city]} {self.weights[sw2.city][sw1.city]}")
            self.best_paths = self.cal_best_paths()
            self.build_mpls_fec()

    def start_monitor(self):
        ts = []
        for i in range(16):
            c1 = City(i)
            s1 = self.switches[c1]

            for c2 in s1.sw_links:
                s2 = self.switches[c2]

                if c1 < c2:
                    ts.append(Ping(s1, s2, 0.1))
        
        for i in range(16):
            ts.append(Pong(self.switches[i], 0.5, self.has_failure, self.no_failure))
        #ts.append(Pong(self.switches[City.PAR], 0.3, self.has_failure, self.no_failure))
        
        for t in ts:
            t.start()

        return ts

    def run(self):
        monitors = self.start_monitor()

        for m in monitors:
            m.join()

    def main(self):
        """Main function"""
        # Don't touch it.
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
