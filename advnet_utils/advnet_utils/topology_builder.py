"""Build base fixed topology"""
# topology based on https://gitlab.ethz.ch/nsg/public/adv-net-2021-project
from advnet_utils.network_API import AdvNetNetworkAPI
from p4utils.mininetlib.log import info
from advnet_utils.get_city_info import get_cities, get_city_short_name, Delay
from advnet_utils.input_parsers import parse_links, parse_additional_links
from networkx import Graph

# we keep it as a constant.
HOSTS_PER_SWITCH = 1

# BASE TOPOLOGY


def build_base_topology(net: AdvNetNetworkAPI, topology_path: str) -> None:
    """Builds the basic topology from config files"""

    # get delay object used to get city delays
    delays = Delay(topology_path)

    # add switches
    cities = get_cities(topology_path + "cities.txt")
    for city in cities:
        _switch_short_name = get_city_short_name(city)
        net.addP4Switch(_switch_short_name)

        # add hosts
        for i in range(HOSTS_PER_SWITCH):
            # add host
            host_name = _switch_short_name + "_h{}".format(i)
            net.addHost(host_name)
            # add link to switch
            net.addLink(host_name, _switch_short_name)

    # add basic links
    links = parse_links(topology_path + "links.txt")
    for src, dst, bw in links:
        # gets a realistic delay between cities
        delay = delays.get_delay(src, dst)

        # adds link params
        _delay = "{}ms".format(delay)
        params = {"bw": float(bw), "delay": _delay}
        net.addLink(src, dst, **params)


# ADD ADDITIONAL LINKS
def add_links_to_topology(net: AdvNetNetworkAPI, topology_path: str, links_file: str, constrains: dict) -> list:
    """Verifies and adds links to topology"""

    # load inputs
    max_links = constrains["max_links"]
    max_total_bw = constrains["max_total_bw"]
    max_bw = constrains["max_bw"]
    links_to_add = parse_additional_links(links_file)

    added_links = []
    # check basic constrains
    # check max links
    _num_links = len(links_to_add)
    if _num_links > max_links:
        raise Exception("You are trying to add {} links. Only {} are possible".format(
            _num_links, max_links))
    # check max invidual bw
    for link in links_to_add:
        if float(link[1]) > max_bw:
            raise Exception(
                "You are exceeding the maximum invidual bw of {}with {}".format(max_bw, link[0]))
    # check max total bw
    _sum_bw = sum(float(x[1]) for x in links_to_add)
    if _sum_bw > max_total_bw:
        raise Exception("You are exceeding the maximum bw. Your links total bandwidth is {}! > {}".format(
            _sum_bw, max_total_bw))

    # get delay object used to get city delays
    delays = Delay(topology_path)

    for link, bw in links_to_add:
        graph = net.g.convertTo(Graph)

        # check if the link exists
        if graph.has_edge(*link):
            raise Exception(
                "Link {} already exists. You can only have one link between cities".format(link))
        # else add the link
        else:
            delay = delays.get_delay(link[0], link[1])
            _delay = "{}ms".format(delay)
            params = {"bw": float(bw), "delay": _delay}
            #params = {"delay": _delay}
            net.addLink(link[0], link[1], **params)
            added_links.append((link))
            info("Adding additional link: {}<->{}\n".format(*link))

    return added_links
