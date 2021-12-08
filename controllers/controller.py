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

        # RSVP Part
        self.current_reservations = {}
        self.link_capacity = self.build_links_capacity()

    def init(self):
        """Basic initialization. Connects to switches and resets state."""
        self.connect_to_switches()
        self.reset_states()

        self.apply_paths(self.cal_shortest_path())
        self.set_mpls_tbl_labels()

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
                dst.controller.table_add("FEC_tbl", "ipv4_forward", ['0.0.0.0/0', dst_ip], [dst.host.mac, str(dst.host_port)])
                logging.debug(f"[{str(dst)}] table_add: FEC_tbl ipv4_forward {['0.0.0.0/0', dst_ip]} {[dst.host.mac, dst.host_port]}")
                for i in range(len(paths) - 1):
                    cur = paths[i]
                    next = paths[i+1]
                    cur_sw = self.switches[cur]
                    cur_port, _, _, next_mac = cur_sw.get_link_to(next)
                    cur_sw.controller.table_add("FEC_tbl", "ipv4_forward", ['0.0.0.0/0', dst_ip], [next_mac, str(cur_port)])
                    logging.debug(f"[{str(cur_sw)}] table_add: FEC_tbl ipv4_forward {['0.0.0.0/0', dst_ip]} {[next_mac, cur_port]}")

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

    def build_links_capacity(self):
        """Builds link capacities dictionary

        Returns:
            dict: {edge: bw}
        """

        links_capacity = {}
        # Iterates all the edges in the topology formed by switches
        for src, dst in self.topo.keep_only_p4switches().edges:
            bw = self.topo.edges[(src, dst)]['bw']
            # add both directions
            links_capacity[(src, dst)] = bw
            links_capacity[(dst, src)] = bw

        return links_capacity

    def set_mpls_tbl_labels(self):
        """We set all the table defaults to reach all the hosts/networks in the network
        """
        for sw_name, controller in self.controller.items():
            # Get all direct hosts and add direct entry
            logging.debug(f"Adding hosts connections to SWITCH {str(sw_name)}")
            for host in self.topo.get_hosts_connected_to(str(sw_name)):
                sw_port = self.topo.node_to_node_port_num(str(sw_name), host)
                host_ip = self.topo.get_host_ip(host)
                host_mac = self.topo.get_host_mac(host)

                # adds direct forwarding rule
                controller.table_add('FEC_tbl', 'ipv4_forward', ['0.0.0.0/0', str(host_ip)], [str(host_mac), str(sw_port)])
                logging.debug(f"[{str(sw_name)}] table_add: FEC_tbl ipv4_forward {['0.0.0.0/0', str(host_ip)]} {[str(host_mac), str(sw_port)]}")

            logging.debug(f"Adding switches connections to SWITCH {str(sw_name)}")
            for switch in self.topo.get_switches_connected_to(str(sw_name)):
                sw_port = self.topo.node_to_node_port_num(str(sw_name), switch)
                # reverse port mac
                other_switch_mac = self.topo.node_to_node_mac(switch, str(sw_name))

                # we add a normal rule and a penultimate one 
                controller.table_add('mpls_tbl', 'mpls_forward', [str(sw_port), '0'], [str(other_switch_mac), str(sw_port)])
                controller.table_add('mpls_tbl', 'penultimate', [str(sw_port), '1'], [str(other_switch_mac), str(sw_port)])
                logging.debug(f"[{str(sw_name)}] table_add: mpls_tbl mpls_forward {[str(sw_port), '0']} {[str(other_switch_mac), str(sw_port)]}")
                logging.debug(f"[{str(sw_name)}] table_add: mpls_tbl penultimate  {[str(sw_port), '1']} {[str(other_switch_mac), str(sw_port)]}")
    
    def build_mpls_path(self, switches_path):
        """Using a path of switches builds the mpls path. In our simplification
        labels are port indexes. 

        Args:
            switches_path (list): path of switches to allocate

        Returns:
            list: label path
        """
        # label path
        label_path = []
        # iterate over all pair of switches in the path
        for current_node, next_node in zip(switches_path, switches_path[1:]):
            # we get sw1->sw2 port number from topo object
            label = self.topo.node_to_node_port_num(current_node, next_node)
            label_path.append(label)
        return label_path

    def get_sorted_paths(self, src, dst):
        """Gets all paths between src, dst 
        sorted by length. This function uses the internal networkx API.

        Args:
            src (str): src name
            dst (str): dst name

        Returns:
            list: paths between src and dst
        """
        paths = self.topo.get_all_paths_between_nodes(src, dst)
        # trim src and dst
        paths = [x[1:-1] for x in paths]
        return paths

    def get_shortest_path(self, src, dst):
        """Computes shortest path. Simple function used to test the system 
        by always allocating the shortest path. 

        Args:
            src (str): src name
            dst (str): dst name

        Returns:
            list: shortest path between src,dst
        """
        
        return self.get_sorted_paths(src, dst)[0]

    def check_if_reservation_fits(self, path, bw):
        """Checks if a the candidate reservation fits in the current
        state of the network. Using the path of switches, checks if all
        the edges (links) have enough space. Otherwise, returns False.

        Args:
            path (list): list of switches
            bw (float): requested bandwidth in mbps

        Returns:
            bool: true if allocation can be performed on path
        """

        # iterates over all pairs of switches (edges)
        for link in zip(path, path[1:]):
            # checks if there is enough capacity 
            if (self.links_capacity[link] - bw) < 0:
                return False
        return True        

    def add_link_capacity(self, path, bw):
        """Adds bw capacity to a all the edges along path. This 
        function is used when an allocation is removed.

        Args:
            path (list): list of switches
            bw (float): requested bandwidth in mbps
        """

        # iterates over all pairs of switches (edges)
        for link in zip(path, path[1:]):   
            # adds capacity   
            self.links_capacity[link] += bw

    def sub_link_capacity(self, path, bw):
        """subtracts bw capacity to a all the edges along path. This 
        function is used when an allocation is added.

        Args:
            path (list): list of switches
            bw (float): requested bandwidth in mbps
        """
        
        # iterates over all pairs of switches (edges)
        for link in zip(path, path[1:]):
            # subtracts capacity
            self.links_capacity[link] -= bw

    def get_available_path(self, src, dst, bw):
        """Checks all paths from src to dst and picks the 
        shortest path that can allocate bw.

        Args:
            src (str): src name
            dst (str): dst name
            bw (float): requested bandwidth in mbps

        Returns:
            list/bool: best path/ False if none
        """
             
        # get all paths sorted from shorter to longer
        paths = self.get_sorted_paths(src, dst)

        for path in paths:
            # checks if the path has capacity
            if self.check_if_reservation_fits(path, bw):
                return path
        return False

    def _add_reservation(self, src, dst, duration, bandwidth, path, update):
        """Adds or updates a single reservation

        Args:
            src (str): src name
            dst (str): dst name
            duration (float): reservation timeout
            bandwidth (float): requested bandwidth in mbps
            path (list): switch path were to allocate the reservation
            update (bool): update flag
        """

        # We build the label path. For that we use self.build_mpls_path and 
        # reverse the returned labels, since our rsvp.p4 will push them in 
        # reverse order.
        label_path = [str(x) for x in self.build_mpls_path(path)[::-1]]

        # Get required info to add a table rule

        # get ingress switch as the first node in the path
        src_gw = path[0]
        # compute the action name using the length of the labels path
        logging.debug(f"Adding hosts connections to SWITCH {str(city_maps[src_gw])}")
        action = 'mpls_ingress_{}_hop'.format(len(label_path))
        # src lpm address
        src_ip = str(self.topo.get_host_ip(src) + '/32')
        # dst exact address
        dst_ip = str(self.topo.get_host_ip(dst))
        # match list
        match = [src_ip, dst_ip]

        # if we have a label path
        if len(label_path) != 0:

            # If the entry is new we simply add it
            if not update:
                entry_handle = self.controllers[city_maps[src_gw]].table_add('FEC_tbl', action, match, label_path)
                # self.set_direct_meter_bandwidth(src_gw, 'rsvp_meter', entry_handle, bandwidth)
            # if the entry is being updated we modify if using its handle  
            else:
                entry = self.current_reservations.get((src, dst), None)
                entry_handle = self.controllers[city_maps[src_gw]].table_modify('FEC_tbl', action, entry['handle'], label_path)
                # self.set_direct_meter_bandwidth(src_gw, 'rsvp_meter', entry_handle, bandwidth)
            
            # udpates controllers link and reservation structures if rules were added succesfully
            if entry_handle:
                self.sub_link_capacity(path, bandwidth)
                self.current_reservations[(src, dst)] = {'timeout': (duration), 'bw': (bandwidth), 'handle': entry_handle, 'path': path}
                print('Successful reservation({}->{}): path: {}'.format(src, dst, '->'.join(path)))
            else:
                print('\033[91mFailed reservation({}->{}): path: {}\033[0m'.format(src, dst, '->'.join(path)))

        else:
            print('Warning: Hosts are connected to the same switch!')

    def add_reservation(self, src, dst, duration, bandwidth):
        """Adds a new reservation. This addition can potentially move or delete
        other allocations.

        Args: src (str): src name dst (str): dst name duration (float):
            reservation timeout bandwidth (float): requested bandwidth in mbps
        """
        
        # locks the self.current_reservations data structure. This is done
        # because there is a thread that could access it concurrently.
        with self.update_lock:

            # if reservation exists, we allocate it again, by just updating the entry
            # for that we set the FLAG UPDATE_ENTRY and restore its link capacity 
            # such the new re-allocation with a possible new bw/prioirty can be done
            # taking new capacities into account.
            UPDATE_ENTRY = False
            if self.current_reservations.get((src, dst), None):
                data = self.current_reservations[(src, dst)]
                path = data['path']
                bw = data['bw']
                # updates link capacities
                self.add_link_capacity(path, bw)
                UPDATE_ENTRY = True

            # finds the best (if exists) path to allocate the requestes reservation
            path = self.get_available_path(src, dst, bandwidth)

            if path:   
                # add or update the reservation 
                self._add_reservation(src, dst, duration, bandwidth, path, UPDATE_ENTRY)

            # Cant be allocated! However, it might be possible to re-allocate things 
            else:
                # if we failed and it was an entry to be updated we remove it
                if UPDATE_ENTRY:
                    data = self.current_reservations[(src, dst)]
                    path = data['path']
                    bw = data['bw']
                    # TRICK: remove it again since we added it to find the path at the beginning.
                    self.sub_link_capacity(path, bw)
                    print('Deleting new allocation. Does not fit anymore!')
                    self.del_reservation(src, dst)
                print('\033[91mRESERVATION FAILURE: no bandwidth available!\033[0m')

    def del_reservation(self, src, dst):
        """Deletes a reservation between src and dst, if exists. To 
        delete the reservation the self.current_reservations data structure 
        is used to retrieve all the needed information. After deleting the reservation
        from the ingress switch, path capacities are updated.

        Args:
            src (str): src name
            dst (str): dst name
        """

        # checks if there is an allocation between src->dst
        entry = self.current_reservations.get((src, dst), None)
        if entry:
            # gets handle to delete entry
            entry_handle = entry['handle']
            # gets src ingress switch
            sw_gw = self.topo.get_host_gateway_name(src)
            # removes table entry using the handle
            self.controllers[city_maps[sw_gw]].table_delete('FEC_tbl', entry_handle, True)
            # updates links capacity
            self.add_link_capacity(entry['path'], entry['bw'])
            # removes the reservation from the controllers memory
            del(self.current_reservations[(src, dst)])
            print('\nRSVP Deleted/Expired Reservation({}->{}): path: {}'.format(src, dst, '->'.join(entry['path'])))
        else:
            print('No entry for {} -> {}'.format(src, dst))

    def del_all_reservations(self):
        """Deletes all the current reservations
        """

        # locks the self.current_reservations data structure. This is done
        # because there is a thread that could access it concurrently.
        with self.update_lock:
            
            # makes a copy of all the reservation pairs
            reservation_keys = list(self.current_reservations.keys())
            for src,dst in reservation_keys:
                self.del_reservation(src, dst)
    
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
