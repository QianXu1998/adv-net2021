from scapy.all import RawPcapReader, DLT_EN10MB, DLT_RAW_ALT, DLT_PPP
import struct
import socket 

IP_PROTOCOL = 0x0800

#constants
ETH_LEN = 14
IP_LEN = 20
# We cant assume after IP there is a transport layer
TCP_LEN = 14
UDP_LEN = 8

UDP_DATA_OFFSET = 12

int_to_protocol = {
    6: "tcp",
    17: "udp"
}

def int2ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))

def find_payload_offset(packet, zeros=32, data_offset=UDP_DATA_OFFSET):
    """Finds payload index"""
    consecutive_zeros = 0
    for i, _byte in enumerate(packet):
        if _byte == 0:
            consecutive_zeros += 1
        else: 
            consecutive_zeros = 0
        if consecutive_zeros >= zeros:
            return i - zeros - data_offset + 1
    return -1 # not found

def pcap_to_flows_sequences(pcap_file):
    """Parses all flows and sequence numbers"""
    # constants
    packet_count = 0
    default_packet_offset = 0
    file = RawPcapReader(pcap_file)
    packet, meta = next(file)
    if hasattr(meta, 'usec'):
        pcap_format = "pcap"
        link_type = file.linktype
    elif hasattr(meta, 'tshigh'):
        pcap_format = "pcapng"
        link_type = meta.linktype
    file.close()
    # check first layer
    if link_type == DLT_EN10MB:
        default_packet_offset += 14
    elif link_type == DLT_RAW_ALT:
        default_packet_offset += 0
    elif link_type == DLT_PPP:
        default_packet_offset += 2

    flow_to_sequences = {}
    with RawPcapReader(pcap_file) as _pcap_reader:
        for packet, meta in _pcap_reader:
            packet_count += 1
            if not packet:
                print("Bad Packet 1: ", packet_count)
                continue
            total_size = meta.wirelen
            # remove first layer (in theory ethernet)
            ethertype = struct.unpack("!H", packet[12:default_packet_offset])[0]
            # skip packet if not ip
            if ethertype != IP_PROTOCOL:
                continue

            #IP LAYER Parsing
            packet = packet[default_packet_offset:]
            version = packet[0]
            ip_version = version >> 4
            # we only accept ipv4
            if ip_version != 4:
                continue

            ip_length = (0x0f & version) * 4
            # ipv4
            src_ip = struct.unpack("!I", packet[12:16])[0]
            dst_ip = struct.unpack("!I", packet[16:20])[0]
            proto = packet[9]

            # for now only parse udp packets
            if proto != 17: # udp
                continue
            packet = packet[ip_length:]
            # try to find the payload of the packet
            # right now our payloads have something in
            # common: they are full of 0s. We assume we found
            # the payload when we find 50 consecutive 0s.
            offset = find_payload_offset(packet)
            payload = packet[offset:offset+UDP_DATA_OFFSET]
            seq, sport, dport = struct.unpack("!QHH", payload)
            # build five tuple
            src = int2ip(src_ip)
            dst = int2ip(dst_ip)
            protocol = int_to_protocol[proto]
            five_tuple = (src, dst, sport, dport, protocol)
            flow_to_sequences.setdefault(five_tuple, set()).add(seq)

    return flow_to_sequences



