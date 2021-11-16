### https://asciiflow.com/#/local/adv-net-2021

import time
import psutil
import subprocess as sp


topo_string = """
                                     ########################################'
                                     ########## Traffic monitoring ##########'
                                     ########################################'

                    The values are in Mbit/s. We show the bit rate for both directions of a link.


                                                                  BER_host0-({}/{})****
                                                                                 \.
                                                             FRA_host0           BER---------
                   EIN_host0            AMS_host0                  \              /          \.
                        \                     \                ({}/{})****  ({}/{})****   ({}/{})****
          MAN_host0 ({}/{})****           ({}/{})****                \------    /              \.
              |             \                   \                           \  /                \.
         ({}/{})****        EIN--({}/{})****--------AMS----------({}/{})****-FRA-({}/{})****----MUN
              |                                      /         \            /   \                 \.
             MAN-({}/{})****--\      LON_host0 ({}/{})**** ({}/{})****     /     \            ({}/{})****
                               \         |         /             \    ----/   ({}/{})****          |
          GLO_host0             \   ({}/{})****   /--({}/{})****--\--/     ------/             MUN_host0
              |                  \       |       /                 \      /
         ({}/{})****             -------LON--------({}/{})****---------PAR--({}/{})****-LIL
              |                 /              \                 /      | \               \.
             GLO-({}/{})****---/                \          ({}/{})****  |  \          ({}/{})****
       -----/                 /                  \             /        |   ---            |
      /                      /      POR_host0     \           REN       |      \        LIL_host0
({}/{})****  ({}/{})****----/           |          \           |        |**  ({}/{})****
     \            /        /      ({}/{})******** ({}/{})** ({}/{})**   |       |
      -----\     /         |            |            \         |        |    PAR_host0
            \   /     ({}/{})****   ---POR---         \     REN_host0   |
             BRI           |       /         \        /                 |
              |            | ({}/{})**** ({}/{})**** /             ({}/{})****
         ({}/{})****       |     /             \    /                   |
              |            \--LIS              MAD--({}/{})****-BAR----/
          BRI_host0            |                |                |
                          ({}/{})****      ({}/{})****      ({}/{})****
                               |                |                |
                           LIS_host0         MAD_host0        BAR_host0
"""

topo_string = topo_string.replace("*","")


def print_traffic(bw):
   """Prints topology with monitored links."""
   tmp = sp.call('clear', shell=True)
   print(topo_string.format(
      bw.pop('BER_h0-BER'),
      bw.pop('BER-BER_h0'),
      bw.pop('FRA_h0-FRA'),
      bw.pop('FRA-FRA_h0'),
      bw.pop('FRA-BER'),
      bw.pop('BER-FRA'),
      bw.pop('BER-MUN'),
      bw.pop('MUN-BER'),
      bw.pop('EIN_h0-EIN'),
      bw.pop('EIN-EIN_h0'),
      bw.pop('AMS_h0-AMS'),
      bw.pop('AMS-AMS_h0'),
      bw.pop('MAN_h0-MAN'),
      bw.pop('MAN-MAN_h0'),
      bw.pop('EIN-AMS'),
      bw.pop('AMS-EIN'),
      bw.pop('AMS-FRA'),
      bw.pop('FRA-AMS'),
      bw.pop('FRA-MUN'),
      bw.pop('MUN-FRA'),
      bw.pop('MAN-LON'),
      bw.pop('LON-MAN'),
      bw.pop('LON-AMS'),
      bw.pop('AMS-LON'),
      bw.pop('AMS-PAR'),
      bw.pop('PAR-AMS'),
      bw.pop('MUN-MUN_h0'),
      bw.pop('MUN_h0-MUN'),
      bw.pop('PAR-FRA'),
      bw.pop('FRA-PAR'),
      bw.pop('LON_h0-LON'),
      bw.pop('LON-LON_h0'),
      bw.pop('LON-FRA'),
      bw.pop('FRA-LON'),
      bw.pop('GLO_h0-GLO'),
      bw.pop('GLO-GLO_h0'),
      bw.pop('LON-PAR'),
      bw.pop('PAR-LON'),
      bw.pop('PAR-LIL'),
      bw.pop('LIL-PAR'),
      bw.pop('GLO-LON'),
      bw.pop('LON-GLO'),
      bw.pop('REN-PAR'),
      bw.pop('PAR-REN'),
      bw.pop('LIL-LIL_h0'),
      bw.pop('LIL_h0-LIL'),
      bw.pop('GLO-BRI'),
      bw.pop('BRI-GLO'),
      bw.pop('BRI-LON'),
      bw.pop('LON-BRI'),
      bw.pop('PAR-PAR_h0'),
      bw.pop('PAR_h0-PAR'),
      bw.pop('POR_h0-POR'),
      bw.pop('POR-POR_h0'),
      bw.pop('LON-MAD'),
      bw.pop('MAD-LON'),
      bw.pop('REN-REN_h0'),
      bw.pop('REN_h0-REN'),
      bw.pop('LIS-LON'),
      bw.pop('LON-LIS'),
      bw.pop('LIS-POR'),
      bw.pop('POR-LIS'),
      bw.pop('POR-MAD'),
      bw.pop('MAD-POR'),
      bw.pop('BAR-PAR'),
      bw.pop('PAR-BAR'),
      bw.pop('BRI-BRI_h0'),
      bw.pop('BRI_h0-BRI'),
      bw.pop('MAD-BAR'),
      bw.pop('BAR-MAD'),
      bw.pop('LIS-LIS_h0'),
      bw.pop('LIS_h0-LIS'),
      bw.pop('MAD-MAD_h0'),
      bw.pop('MAD_h0-MAD'),
      bw.pop('BAR-BAR_h0'),
      bw.pop('BAR_h0-BAR')
   ))

   if len(bw) > 0:
      custom_string = 'Custom links:\n'
      while len(bw) > 0:
         key1 = list(bw.keys())[0]
         nodes = key1.split('-')
         key2 = nodes[1] + '-' + nodes[0]
         custom_string += key1 +':\t({}/{})\t'.format(bw.pop(key1), bw.pop(key2))
      print(custom_string)


def get_intfs(topo):
   """Returns all the interfaces pairs given a topology object.

   Args:
      topo (:py:class:`p4utils.utils.topology.NetworkGraph`): Topology object

   Returns:
      dict: A dictionary indexed by ``node1node2`` that contains the interface
      names of the interface on ``node1`` facing ``node2``.
   """
   intfs = {}
   for node1, node2, data in topo.edges(data=True):
      intfs[(node1+'-'+node2)] = (data['intfName1'], data['intfName2'], topo.isHost(node1))
      intfs[(node2+'-'+node1)] = (data['intfName2'], data['intfName1'], topo.isHost(node2))

   return intfs


def monitor_network(topo):
   """Monitors all the links of the topology.

   Args:
      topo (:py:class:`p4utils.utils.topology.NetworkGraph`): Topology object
   """

   # Get interface dict
   intfs = get_intfs(topo)

   # Generate empty link_traffic dict
   link_traffic = {}
   for key in intfs:
      link_traffic[key] = []

   # Instantiate empty bandwidth dict
   bw = {}

   # Iterate
   i = 0
   while True:
      try:
         # Get network stats
         net_stats = psutil.net_io_counters(pernic=True)

         # Populate link_traffic dict
         for key, value in intfs.items():
            intf, intf_neigh, host = value
            if host:
               link_traffic[key].append((time.time(), net_stats[intf_neigh].bytes_recv*8))
            else:
               pass
               link_traffic[key].append((time.time(), net_stats[intf].bytes_sent*8))
            if len(link_traffic[key]) > 10:
                  link_traffic[key].pop(0)

         # Populate bw dict
         for key, t in link_traffic.items():
            if len(t) > 1:
               duration = float(t[-1][0] - t[0][0])
               traffic = float(t[-1][1] - t[0][1])
               bw[key] =  "\033[01m{:4.1f}\033[0m".format((traffic/duration)/1000000)

         time.sleep(0.1)
         if i == 5:
            print_traffic(bw)
            i = 0
         else:
            i += 1

      except:
         print("There is no network to monitor!")
         break

if __name__ == '__main__':
   from p4utils.utils.helper import load_topo
   monitor_network(load_topo('../../topology.json'))