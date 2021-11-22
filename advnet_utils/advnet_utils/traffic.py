import csv
import time
import math
import socket
import struct

from advnet_utils.utils import _parse_rate, _parse_size

# Network constants (bytes)
MTU = 1500
ETHERNET_HEADER = 26
IPV4_HEADER = 20
UDP_HEADER = 8
TCP_HEADER = 20

# Transport constants (bytes)
TCP_MAX_PAYLOAD = MTU - IPV4_HEADER - TCP_HEADER
UDP_MAX_PAYLOAD = MTU - IPV4_HEADER - UDP_HEADER

# Custom constants (packets)
UDP_MAX_BURST_SIZE = 1

# https://www.man7.org/linux/man-pages/man7/socket.7.html
# Default value is 212992
TCP_BUFFER_SIZE = int(212992*1.5)
UDP_BUFFER_SIZE = int(212992*1.5)

# /usr/include/linux/tcp.h
TCP_INFO = [
    'tcpi_state', 
    'tcpi_ca_state',
    'tcpi_retransmits',
    'tcpi_probes',
    'tcpi_backoff',
    'tcpi_options',
    'tcpi_snd_wscale_tcpi_rcv_wscale',
    'tcpi_delivery_rate_app_limited',
    'tcpi_rto',
    'tcpi_ato',
    'tcpi_snd_mss',
    'tcpi_rcv_mss',
    'tcpi_unacked',
    'tcpi_sacked',
    'tcpi_lost',
    'tcpi_retrans',
    'tcpi_fackets',
    'tcpi_last_data_sent',
    'tcpi_last_ack_sent',
    'tcpi_last_data_recv',
    'tcpi_last_ack_recv',
    'tcpi_pmtu',
    'tcpi_rcv_ssthresh',
    'tcpi_rtt',
    'tcpi_rttvar',
    'tcpi_snd_ssthresh',
    'tcpi_snd_cwnd',
    'tcpi_advmss',
    'tcpi_reordering',
    'tcpi_rcv_rtt',
    'tcpi_rcv_space', 
    'tcpi_total_retrans',
    'tcpi_pacing_rate',
    'tcpi_max_pacing_rate',
    'tcpi_bytes_acked',
    'tcpi_bytes_received',
    'tcpi_segs_out',
    'tcpi_segs_in',
    'tcpi_notsent_bytes',
    'tcpi_min_rtt',
    'tcpi_data_segs_in',
    'tcpi_data_segs_out',
    'tcpi_delivery_rate',
    'tcpi_busy_time',
    'tcpi_rwnd_limited',
    'tcpi_sndbuf_limited'
]

TCP_INFO_BYTES='<BBBBBBBBLLLLLLLLLLLLLLLLLLLLLLLLQQQQLLLLLLQQQQ'


def get_tcp_info(s):
    """Generate a dictionary containing all the information 
    of the TCP socket.
    
    Args:
        s (socket.socket): TCP socket
    """
    raw_info = s.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 192)
    tuple_info = struct.unpack(TCP_INFO_BYTES, raw_info)
    dict_info = {}
    for i in range(len(tuple_info)):
        dict_info[TCP_INFO[i]] = tuple_info[i]
    return dict_info
  

## UDP
def send_udp_flow(dst='127.0.0.1',
                  sport=5000,
                  dport=5001,
                  tos=0,
                  rate='10 Mbps',
                  duration=10,
                  payload_size=UDP_MAX_PAYLOAD,
                  max_burst_size=UDP_MAX_BURST_SIZE,
                  out_csv='send.csv',
                  **kwargs):
    """UDP sending function that keeps a constant rate and logs sent packets to a file.
    Args:
        dst (str, optional): Destination IP. Defaults to '127.0.0.1'.
        sport (int, optional): Source port. Defaults to 5000.
        dport (int, optional): Destination port. Defaults to 5001.
        tos (int, optional): Type of Service. Defaults to 0.        
        rate (float or str, optional): Flow rate. Defaults to '10 Mbps'.
        duration (float, optional): Flow duration in seconds. Defaults to 10.
        payload_size (int, optional): UDP payload in bytes. Defaults to UDP_MAX_PAYLOAD.
        max_burst_size (int, optional): UDP burst size in number of packets. Defaults to UDP_MAX_BURST_SIZE.
        out_csv (str, optional): Log of sent packets with timestamps. Defaults to 'send.csv'.
    
    Note:
        ``max_burst_size`` cannot be smaller than ``1``.
    """
    # Convert rates to B/s
    rate = _parse_rate(rate)
    #print("rate", rate, "\n")

    # Sanity checks
    assert isinstance(dst, str) # Desination IP must be a string
    assert rate > 0 # The flow must have a positive rate
    assert isinstance(sport, int) and sport > 0 and sport < 2**16 # Check valid port number
    assert isinstance(dport, int) and dport > 0 and dport < 2**16 # Check valid port number
    assert isinstance(tos, int) and tos >= 0 and tos < 2**8 # Check valid ToS value
    assert (isinstance(duration, float) or isinstance(duration, int)) and duration >= 0 # Duration must be positive
    assert isinstance(payload_size, int) and payload_size > 12 and payload_size <= UDP_MAX_PAYLOAD # Check valid payload size
    assert isinstance(max_burst_size, int) and max_burst_size > 0 # The maximum burst size must be at least 1 packet

    # Open .csv file
    output = open(out_csv, 'w', newline='')
    # Fields of the .csv
    fields = ['seq_num', 't_timestamp']
    # CSV writer
    csv_writer = csv.DictWriter(output, fieldnames=fields)
    # Write header
    csv_writer.writeheader()

    # Open socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_IP, socket.IP_TOS, tos)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, UDP_BUFFER_SIZE) 

    s.setblocking(True)
    s.bind(('', sport))

    # Initialize token bucket
    token_bucket = 0
    # Initialize burst counter
    brst_count = 0
    # Initialize sequence number
    seq_num = 1

    # Save start time
    startTime = lastTime = time.time()

    # Compute end time
    if duration > 0:
        endTime = startTime + duration
    else:
        endTime = None

    while True:
        while token_bucket >= payload_size and brst_count < max_burst_size:
            # Get timestamp
            timestamp = time.time()
            # Send packet
            # concatenates sport, dport and sequence number in the packet payload
            payload =  seq_num.to_bytes(8, byteorder='big') + sport.to_bytes(2, byteorder="big") + dport.to_bytes(2, byteorder="big") + bytes(payload_size - 12)

            s.sendto(payload, (dst, dport))

            # Save log to the .csv file
            csv_writer.writerow({'seq_num': seq_num, 't_timestamp': timestamp})
            # Increase the sequence number
            seq_num += 1
            # Increse the burst counter
            brst_count += 1
            # Remove tokens from the bucket
            token_bucket -= payload_size + ETHERNET_HEADER + IPV4_HEADER + UDP_HEADER 
            # If the sequence number needs more bytes, raise exception
            if math.ceil(seq_num.bit_length() / 8) > payload_size-4:
                raise Exception('cannot store sequence number in packet payload!')
        
        # Get current time
        currentTime = time.time()

        # Break if duration expired
        if endTime is not None:
            if currentTime >= endTime:
                break

        # Compute elapsed time
        diffTime = currentTime - lastTime
        lastTime = currentTime

        # Add tokens to bucket
        token_bucket += rate * diffTime
        # Reset the burst counter
        brst_count = 0

        # Sleep for at least one packet in the token_bucket
        time.sleep(max(payload_size - token_bucket, 0) / rate)

    # Close socket
    s.close()
    # Close .csv file
    output.close()


def recv_udp_flow(sport=5000,
                  dport=5001,
                  duration=10,
                  out_csv='recv.csv',
                  **kwargs):
    """UDP Receiving function.

    Args:
        sport (int, optional): Source port of the flow. Defaults to 5000.
        dport (int, optional): Port to listen on. Defaults to 5001.
        duration (float, optional): Listening time in seconds. Defaults to 10.
        out_csv (str, optional): Log of received packets with timestamps. Defaults to 'recv.csv'.
    """
    # Sanity checks
    assert isinstance(sport, int) and sport > 0 and sport < 2**16 # Check valid port number
    assert isinstance(dport, int) and dport > 0 and dport < 2**16 # Check valid port number
    assert (isinstance(duration, float) or isinstance(duration, int)) and duration >= 0 # Duration must be positive

    # Open .csv file
    output = open(out_csv, 'w', newline='')
    # Fields of the .csv
    fields = ['seq_num', 'r_timestamp']
    # CSV writer
    csv_writer = csv.DictWriter(output, fieldnames=fields)
    # Write header
    csv_writer.writeheader()

    # Open socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, UDP_BUFFER_SIZE) 
    s.bind(('', dport))

    # Save start time
    startTime = time.time()

    # Compute end time
    if duration > 0:
        endTime = startTime + duration
    else:
        endTime = None

    # Receive packets
    while True:
        # Get current time
        currentTime = time.time()

        # Break if duration expired
        if endTime is not None:
            # Get current time
            currentTime = time.time()
            if currentTime >= endTime:
                break
            # Update timeout
            s.settimeout(max(endTime - time.time(), 0))
        else:
            s.setblocking(True)

        try:
            # Get data from socket
            data, address = s.recvfrom(4096)
            # Get timestamp
            timestamp = time.time()
            # Get source address
            _, pkt_sport = address

            # Only accept packets from the expected source
            if pkt_sport == sport:
                # Parse sequence number
                seq_num = int.from_bytes(data[:8], byteorder='big')
                # Save log to the .csv file
                csv_writer.writerow({'seq_num': seq_num, 'r_timestamp': timestamp})
        # If timeout expired
        except socket.timeout:
            break

    # Close socket
    s.close()
    # Close .csv file
    output.flush()
    output.close()


def send_tcp_flow(dst='127.0.0.1',
                  sport=5000,
                  dport=5001,
                  tos=0,
                  send_size=0,
                  rate=0,
                  duration=10,
                  payload_size=TCP_MAX_PAYLOAD,
                  out_csv='send.csv',
                  **kwargs):
    """TCP sending function that keeps a constant rate and logs sent packets to a file.

    Args:
        dst (str, optional): Destination IP. Defaults to '127.0.0.1'.
        sport (int, optional): Source port. Defaults to 5000.
        dport (int, optional): Destination port. Defaults to 5001.
        tos (int, optional): Type of Service. Defaults to 0.
        send_size (int, optional): Total amount of data to send. Defaults to 0.
        rate (float or str, optional): Maximum flow rate. Defaults to 0.
        duration (float, optional): Flow duration in seconds. Defaults to 10.
        payload_size (int, optional): TCP payload in bytes. Defaults to TCP_MAX_PAYLOAD.
        out_csv (str, optional): Log of sent packets with timestamps. Defaults to 'send.csv'.

    Note:
        - If ``send_size`` is set to ``0`` then the sender will continuously send data. Otherwise,
          it will send the selected amount of data.
        - If ``duration`` is set to ``0``, then the sender will wait indefinitely for flow completion.
    """
    # Convert rates to B/s
    rate = _parse_rate(rate)
    # Convert send_size to Bytes
    send_size = _parse_size(send_size)

    # Sanity checks
    assert isinstance(dst, str) # Desination IP must be a string
    assert rate >= 0 # The flow must not be negative
    assert send_size >= 0 # The flow size must not be negative
    assert (rate > 0 and duration > 0) or send_size > 0 # Guarantee that some data are actually sent
    assert isinstance(sport, int) and sport > 0 and sport < 2**16 # Check valid port number
    assert isinstance(dport, int) and dport > 0 and dport < 2**16 # Check valid port number
    assert isinstance(tos, int) and tos >= 0 and tos < 2**8 # Check valid ToS value
    assert (isinstance(duration, float) or isinstance(duration, int)) and duration >= 0 # Duration must not be negative
    assert isinstance(payload_size, int) and payload_size > 0 and payload_size <= TCP_MAX_PAYLOAD # Check valid payload size

    # Compute tot_bytes
    if send_size > 0:
        tot_bytes = send_size
    else:
        tot_bytes = math.ceil(rate*duration)

    # Open .csv file
    output = open(out_csv, 'w', newline='')
    # Fields of the .csv
    fields = ['rtt']
    # CSV writer
    csv_writer = csv.DictWriter(output, fieldnames=fields)
    # Write header
    csv_writer.writeheader()
    # Save tot_bytes as first line
    csv_writer.writerow({'rtt': tot_bytes})

    # Open socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_IP, socket.IP_TOS, tos)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_TCP, socket.TCP_MAXSEG, payload_size)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, TCP_BUFFER_SIZE) 
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, TCP_BUFFER_SIZE)
    s.bind(('', sport))

    # Create two fixed payloads
    payload = bytes(payload_size)
    # Init tcpi_segs_out counter
    tcpi_segs_out = 0

    # Save start time
    startTime = time.time()

    # Compute end time
    if duration > 0:
        endTime = startTime + duration
    else:
        endTime = None

    # Update timeout
    if endTime is not None:
        s.settimeout(max(endTime - time.time(), 0))
    else:
        s.setblocking(True)

    try:
        # Establish connection
        s.connect((dst, dport))
    # If timeout expired
    except socket.timeout:
        # Close socket
        s.close()
        # Close .csv file
        output.close()
        # Terminate function
        return

    # bulk based sender
    while True:
        # Bytes to send
        bytes_to_send = min(tot_bytes, payload_size)
        # If there are actual data to send
        if bytes_to_send > 0:
            # Update timeouts
            if endTime is not None:
                s.settimeout(max(endTime - time.time(), 0))
            else:
                s.setblocking(True)

            try:
                # Send packet
                sent_bytes = s.send(payload[:bytes_to_send])
                # Break if remote endpoint closed connection
                if not sent_bytes:
                    break
            # If timeout expired
            except socket.timeout:
                # Exit loop
                break

            tcp_info = get_tcp_info(s)
            if tcp_info['tcpi_segs_out'] > tcpi_segs_out:
                # Update count
                tcpi_segs_out = tcp_info['tcpi_segs_out']
                # Get RTT
                rtt = tcp_info['tcpi_rtt']
                # Save log to the .csv file
                csv_writer.writerow({'rtt': rtt})

            # Remove sent_bytes from tot_bytes
            tot_bytes -= sent_bytes

        # Break if all the data were sent
        if tot_bytes == 0:
            break
        
        # Break if duration expired
        if endTime is not None:
            # Get current time
            currentTime = time.time()
            if currentTime >= endTime:
                break

    # Write elapsed time
    csv_writer.writerow({'rtt': time.time() - startTime})
    # Write unsent bytes
    csv_writer.writerow({'rtt': tot_bytes})
    # Close socket
    s.close()
    # Close .csv file
    output.close()


def recv_tcp_flow(sport=5000,
                  dport=5001,
                  duration=10,
                  **kwargs):
    """TCP Receiving function.

    Args:
        sport (int, optional): Source port of the flow. Defaults to 5000.
        dport (int, optional): Port to listen on. Defaults to 5001.
        duration (float, optional): Listening time in seconds. Defaults to 10.
    """
    # Sanity checks
    assert isinstance(sport, int) and sport > 0 and sport < 2**16 # Check valid port number
    assert isinstance(dport, int) and dport > 0 and dport < 2**16 # Check valid port number
    assert (isinstance(duration, float) or isinstance(duration, int)) and duration >= 0 # Duration must be positive

    # Open socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, TCP_BUFFER_SIZE) 
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, TCP_BUFFER_SIZE)
    s.bind(('', dport))
    s.listen()

    # Save start time
    startTime = time.time()
    # Compute end time
    if duration > 0:
        endTime = startTime + duration
    else:
        endTime = None

    # Wait for the right connection
    while True:
        # Break if duration expired
        if endTime is not None:
            # Get current time
            currentTime = time.time()
            if currentTime >= endTime:
                # Close socket
                s.close()
                # Terminate function
                return
            # Update timeout
            s.settimeout(max(endTime - time.time(), 0))
        else:
            s.setblocking(True)

        try:
            # Establish connection
            conn, address = s.accept()
        # If timeout expired
        except socket.timeout:
            # Close socket
            s.close()
            # Terminate function
            return
        
        # Get connection source port
        _, conn_sport = address

        # Only accept connections from the expected source
        if conn_sport == sport:
            break
        else:
            # Close wrong connection
            conn.close()

    # Receive packets
    while True:
        # Break if duration expired
        if endTime is not None:
            # Get current time
            currentTime = time.time()
            if currentTime >= endTime:
                break
            # Update timeout
            s.settimeout(max(endTime - time.time(), 0))
        else:
            s.setblocking(True)
                    
        try:
            # Get data from socket
            data = conn.recv(2048)
            # Break if remote endpoint closed connection
            if not data:
                break
        # If timeout expired
        except socket.timeout:
            break

    # Close connection
    conn.close()
    # Close socket
    s.close()
