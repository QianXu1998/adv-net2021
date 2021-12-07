"""Template of an empty global controller"""
import argparse
from os import path
from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
from enum import IntEnum
import logging
logging.basicConfig(filename='/tmp/controller.log', format="[%(levelname)s] %(message)s", level=logging.DEBUG)

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

# TODO: cal weights by delay?
initial_weights = {
    City.AMS : {
        City.EIN : 1,
        City.LON : 2,
        City.FRA : 2,
        City.PAR : 5
    },
    City.BAR : {
        City.PAR : 6,
        City.MAD : 4
    },
    City.BER : {
        City.FRA : 3,
        City.MUN : 4
    },
    City.BRI : {
        City.LON : 1
    },
    City.EIN : {
        City.AMS : 1
    },
    City.FRA : {
        City.LON : 5,
        City.AMS : 2,
        City.PAR : 4,
        City.MUN : 2,
        City.BER : 3
    },
    City.GLO : {
        City.LON : 1,
    },
    City.LIL : {
        City.PAR : 1
    },
    City.LIS : {
        City.POR : 1,
        City.LON : 9
    },
    City.LON : {
        City.LIS : 9,
        City.MAD : 8,
        City.PAR : 3,
        City.FRA : 5,
        City.AMS : 2,
        City.MAN : 1,
        City.GLO : 1,
        City.BRI : 1
    },
    City.MAD : {
        City.POR : 4,
        City.LON : 8,
        City.BAR : 4
    },
    City.MAN : {
        City.LON : 1
    },
    City.MUN : {
        City.BER : 4,
        City.FRA : 2
    },
    City.PAR : {
        City.LIL : 1,
        City.REN : 1,
        City.AMS : 5,
        City.FRA : 4,
        City.BAR : 6,
        City.LON : 3
    },
    City.POR : {
        City.MAD : 4,
        City.LIS : 1
    },
    City.REN : {
        City.PAR : 1
    }
}

class Switch:

    def __init__(self, city: City):
        self.city = city
        self.sw_links = {}
        self.host = Host(self)
        self.controller = None # type: SimpleSwitchThriftAPI

    def get_link_to(self, city: City):
        #logging.debug(self.sw_links)
        next_sw = self.sw_links[city]['sw']
        return self.sw_links[city]['port'], self.sw_links[city]['mac'], next_sw.sw_links[self.city]['port'], next_sw.sw_links[self.city]['mac']

    @property
    def host_port(self):
        return self.host.sw_port

    def __str__(self):
        return str(self.city)

class Host:
    def __init__(self, sw: Switch):
        self.city_sw = sw
        self.mac = None
        self.ip = None
        self.sw_port = None

    def __str__(self) -> str:
        return f"{str(self.city_sw)}_h0"



class Controller(object):

    def __init__(self, base_traffic):
        self.base_traffic_file = base_traffic
        self.topo = load_topo('topology.json')
        self.controllers = {}
        self.weights = initial_weights.copy()
        self.switches = [Switch(City(i)) for i in range(16)]
        self.init()

        self.sanity_check()

    def init(self):
        """Basic initialization. Connects to switches and resets state."""
        self.connect_to_switches()
        self.reset_states()

        self.apply_paths(self.cal_shortest_path())

    def pprint_topo(self):
        for sw in self.switches:
            for neigh_city, attrs in sw.sw_links.items():
                logging.debug(f"{str(sw)}:{attrs['port']} -> {str(neigh_city)} port_mac: {attrs['mac']}")
            logging.debug(f"{str(sw)}:{sw.host_port} -> {str(sw.host)}")

    def apply_paths(self, paths: dict):
        for city1, city1_d in paths.items():
            for city2, paths in city1_d.items():
                logging.debug(f"Applying {paths}")
                dst = self.switches[paths[-1]]
                dst_ip = dst.host.ip
                dst.controller.table_add("ipv4_lpm", "ipv4_forward", [dst_ip], [dst.host.mac, str(dst.host_port)])
                logging.debug(f"[{str(dst)}] table_add: ipv4_lpm ipv4_forward {[dst_ip]} {[dst.host.mac, dst.host_port]}")
                for i in range(len(paths) - 1):
                    cur = paths[i]
                    next = paths[i+1]
                    cur_sw = self.switches[cur]
                    cur_port, _, _, next_mac = cur_sw.get_link_to(next)
                    cur_sw.controller.table_add("ipv4_lpm", "ipv4_forward", [dst_ip], [next_mac, str(cur_port)])
                    logging.debug(f"[{str(cur_sw)}] table_add: ipv4_lpm ipv4_forward {[dst_ip]} {[next_mac, cur_port]}")


    def cal_shortest_path(self):
        paths = [ [ -1 for __ in range(16) ] for _ in range(16)]
        dis = [ [ 0xFFFF for __ in range(16) ] for _ in range(16)]

        for city1, c1_w in self.weights.items():
            for city2, w in c1_w.items():
                dis[city1][city2] = w

        for k in range(16):
            for i in range(16):
                for j in range(16):
                    d = dis[i][k] + dis[k][j]
                    if dis[i][j] > d:
                        dis[i][j] = d
                        paths[i][j] = k
        
        def _retrieve_path(start, end):
            if paths[start][end] == -1:
                return [City(start), City(end)]

            k = paths[start][end]
            return _retrieve_path(start, k)[:-1] + _retrieve_path(k, end)

        results = {}

        for i in range(16):
            results[City(i)] = {}
            for j in range(16):
                if i != j:
                    results[City(i)][City(j)] = _retrieve_path(i, j)
                    #logging.debug(f"{str(City(i))} -> {str(City(j))}: {results[City(i)][City(j)]}")

        return results

    def reset_states(self):
        """Resets switches state"""
        [controller.reset_state() for controller in self.controllers.values()]

    def connect_to_switches(self):
        """Connects to switches"""
        logging.debug(f"{self.topo.get_node_intfs()}")
        for p4switch in self.topo.get_p4switches():
            thrift_port = self.topo.get_thrift_port(p4switch)
            self.controllers[city_maps[p4switch]] = SimpleSwitchThriftAPI(thrift_port)
            logging.debug(f"Switch: {p4switch} port: {thrift_port}")

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
                    sw.host.ip = attrs['ip']
                    sw.host.mac = attrs['addr']
                    sw.host.sw_port = attrs['port_neigh']

            for _, attrs in city_intfs.items():
                if "delay" in attrs and attrs['node'] == city_name:
                    neigh_city = city_maps[attrs['node_neigh']]
                    neigh_switch = self.switches[neigh_city]
                    sw.sw_links[neigh_city] = {
                        "port" : attrs['port'],
                        "delay" : attrs['delay'],
                        "mac" : attrs['addr'],
                        "sw" : neigh_switch
                    }
        
        self.pprint_topo()


    def sanity_check(self):
        for city1, city_weights in self.weights.items():
            for city2, w in city_weights.items():
                if city1 in self.weights[city2] and self.weights[city2][city1] != w:
                    logging.warning(f"Mismatched weights between {city1} and {city2}!")
                
                if city1 not in self.weights[city2]:
                    logging.warning(f"Reverse weight doesn't exist for {city2} -> {city1}, setting it to {w}")
                    self.weights[city2][city1] = w

    def run(self):
        """Run function"""

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
    controller = Controller(args.base_traffic)
    controller.main()
