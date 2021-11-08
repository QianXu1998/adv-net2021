"""Parsers for different input files"""

import csv


def _get_lines_and_clean(lines):
    """Removes all the lines starting with # and //"""
    return [x for x in lines if not x.startswith("#") and not x.startswith("//")]


def parse_links(links_file):
    """Parses regular links file"""

    links = []
    with open(links_file, "r") as f:
        raw_link = f.readlines()
        for link in raw_link:
            # filter comments
            if link.startswith("#") or link.startswith("//"):
                continue
            src, dst, bw = link.strip().split()
            links.append((src, dst, bw))
    return links


def parse_additional_links(additional_links_file):
    "Parses additional links file"

    raw = open(additional_links_file, "r").read()
    lines = raw.splitlines()
    lines = _get_lines_and_clean(lines)
    dialect = csv.Sniffer().sniff(raw)
    reader = csv.DictReader(lines, dialect=dialect)
    links = []
    for row in reader:
        # Re-format rows
        links.append(
            [(row["src_switch"], row["dst_switch"]), float(row["bw"])])
    return links


def parse_link_failures(failure_links_file):
    "Parses failure links file"

    raw = open(failure_links_file, "r").read()
    lines = raw.splitlines()
    lines = _get_lines_and_clean(lines)
    dialect = csv.Sniffer().sniff(raw)
    reader = csv.DictReader(lines, dialect=dialect)
    link_failures = []
    for row in reader:
        # Re-format rows
        link_failures.append([(row["src_switch"], row["dst_switch"]), float(
            row["failure_time"]), float(row["duration"])])
    return link_failures


def parse_traffic(traffic_file):
    """Parses a traffic file"""

    raw = open(traffic_file, "r").read()
    lines = raw.splitlines()
    lines = _get_lines_and_clean(lines)
    dialect = csv.Sniffer().sniff(raw)
    reader = csv.DictReader(lines, dialect=dialect)
    flows = []
    for row in reader:
        # Re-format rows
        row["sport"] = int(row["sport"])
        row["dport"] = int(row["dport"])
        row["start_time"] = float(row["start_time"])
        flows.append(row)
    return flows
