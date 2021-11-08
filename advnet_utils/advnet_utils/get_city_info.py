"""Util script to get city distance and delay info"""

# API used to get city distances https://www.distance24.org/api.xhtml

import requests
import json
import os
import math

from itertools import combinations
from ast import literal_eval


def get_cities(file_name):
    cities = open(file_name, "r").readlines()
    cities = [x.strip() for x in cities]
    return cities


def get_city_short_name(city):
    """Transforms city name to short caps name"""
    return city.upper()[:3]


def get_cities_short_name(cities):
    """Returns city short name"""
    short_name = [get_city_short_name(x) for x in cities]
    return short_name


def get_city_pairs(cities):
    """Returns all city pairs"""
    return list(combinations(cities, 2))


def get_citiy_distance(city1, city2):
    """Returns the distance in KM between cities"""
    url = "https://www.distance24.org/route.json?stops={}|{}"
    res = requests.request("GET", url.format(city1, city2))

    if res.status_code == 200:
        info = res.json()
        distance = info["distance"]
        return distance
    else:
        print("Could not find the distance between {}<->{}".format(city1, city2))
        return -1


def get_all_distance_pairs(cities_file):
    """Get all city distance pairs"""
    city_pairs = get_city_pairs(get_cities(cities_file))
    city_distance_pairs = {}
    for pair in city_pairs:
        distance = get_citiy_distance(*pair)
        city_distance_pairs[tuple(pair)] = distance

    return city_distance_pairs


def save_all_distance_pairs(cities_file, out_file):
    """Get distance pairs and save them"""
    distances = get_all_distance_pairs(cities_file)
    distances = {str(k): v for k, v in distances.items()}
    json.dump(distances, open(out_file, "w"))


def load_all_distance_pairs(pairs_file):
    """Loads the json distances file"""
    distances = json.load(open(pairs_file, "r"))
    distances = {literal_eval(k): v for k, v in distances.items()}

    # change long name for short name
    _distances = {}
    for k, v in distances.items():
        _k = tuple(get_city_short_name(x) for x in k)
        _distances[_k] = v

    return _distances


# DELAY HELPER
# ============

class Delay(object):
    """Object to get delay between cities in the topology"""

    def __init__(self, topo_info_path):
        self.topo_info_path = topo_info_path
        self.distances_file = self.topo_info_path + "city_distances.json"
        self.cities = get_cities_short_name(
            get_cities(self.topo_info_path + "cities.txt"))
        self.load_distances()

    def load_distances(self):
        """Loads or gets city distances"""
        if os.path.exists(self.distances_file):
            self.distances = load_all_distance_pairs(self.distances_file)
        else:
            # create and save distances
            save_all_distance_pairs(
                self.topo_info_path + "cities.txt", self.distances_file)
            self.distances = load_all_distance_pairs(self.distances_file)

    def get_distance(self, src, dst):
        """Get distance between 2 cities"""

        # get distance in km
        if self.distances.get((src, dst), None):
            distance = self.distances.get((src, dst))

        if self.distances.get((dst, src), None):
            distance = self.distances.get((dst, src))

        return distance

    def distance_to_rtt(self, distance):
        """Returns rtt in ms given a distance

        All based in the following:
        https://hpbn.co/primer-on-latency-and-bandwidth/
        https://wondernetwork.com/pings

        Each 250km 5ms RTT. This has been verfied with real pings and distance
        measurements. 

        For this we divide the distance by 250km and round to the closest value.

        Less or equal to 250km -> 5ms
        500km  -> 10ms
        750km  -> 15ms
        1000km -> 20ms
        1250km -> 25ms
        1500km -> 30ms
        1750km -> 35ms
        2000km -> 40ms
        2000km+ -> 50ms
        """

        # compute times 250
        if distance == 250 or distance < 250:
            return 5
        elif distance > 2000:
            return 50
        else:
            _times_250 = round(distance/250)
            #_times_250 = math.ceil(distance/250)
            return _times_250 * 5  # 5ms per 250km

    def get_rtt(self, src, dst):
        """Get the rtt between 2 cities"""

        # check if cities exist
        if src not in self.cities:
            assert("City {} does not exist".format(src))
        if dst not in self.cities:
            assert("City {} does not exist".format(dst))

        # get distance and delay
        distance = self.get_distance(src, dst)
        # rtt to one way delay
        return self.distance_to_rtt(distance)

    def get_delay(self, src, dst):
        """Returns the delay between cities."""
        return self.get_rtt(src, dst)/2
