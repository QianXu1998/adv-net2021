topo_string = """
                                     ########################################'
                                     ########## Traffic monitoring ##########'
                                     ########################################'

                    The values are in Mbit/s. We show the bit rate for both directions of a link.


              EIN_host0     AMS_host0    BER_host0-({}/{})
                   \              \                     \.
   MAN_host0      ({}/{})       ({}/{})   FRA_host0     BER--\.
       |               \            \           \        /  ({}/{})
    ({}/{})            EIN--({}/{})---AMS--   ({}/{})({}/{})     \.
       |                           /  \    \      \    /      /-MUN
      MAN--({}/{})  LON_host0  ({}/{}) \   ({}/{})--FRA-({}/{})  \.
               \        |        /    ({}/{})  ---/ /           ({}/{})
   GLO_host0    \    ({}/{})    /--({}/{})-\--/ ({}/{})            |
       |         --\    |      /            \     /             MUN_host0
    ({}/{})({}/{})-----LON------({}/{})-------PAR--({}/{})-LIL
       |      /   /           \              / |  \         \.
      GLO----/   /  POR_host0  \        ({}/{})| ({}/{})   ({}/{})
     /          /       |     ({}/{})    /     |    |         |
    /      -----|    ({}/{})     \     REN     | PAR_host0 LIL_host0
({}/{})({}/{})  |       |         |    |       |
   \     /   ({}/{})   POR        | ({}/{}) ({}/{})
    \   /       |      /  \       |    |       |
     \ /        |  ({}/{})({}/{}) | REN_host0  |
      BRI       |    /      \     |            |
       |        \--LIS      MAD-------({}/{})-BAR
    ({}/{})         |        |                 |
       |         ({}/{})  ({}/{})           ({}/{})
   BRI_host0        |        |                 |
                LIS_host0 MAD_host0         BAR_host0
"""


def test():
   print(topo_string.format(*["9.11" for x in range(76)]))

test()