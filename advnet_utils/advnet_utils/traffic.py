import csv
import time
import math
import socket

from advnet_utils.utils import _parse_rate, _parse_size

# Network constants (bytes)
MTU = 1500
IPV4_HEADER = 20
UDP_HEADER = 8
TCP_HEADER = 20

# Transport constants (bytes)
TCP_MAX_PAYLOAD = MTU - IPV4_HEADER - TCP_HEADER
UDP_MAX_PAYLOAD = MTU - IPV4_HEADER - UDP_HEADER

# Custom constants (packets)
UDP_MAX_BURST_SIZE = 1
TCP_MAX_BURST_SIZE = 1

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
    assert isinstance(payload_size, int) and payload_size > 0 and payload_size <= UDP_MAX_PAYLOAD # Check valid payload size
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
    s.setblocking(True)
    s.bind(('', sport))

    # Initialize token bucket
    token_bucket = 0
    # Initialize burst counter
    brst_count = 0
    # Initialize sequence number
    seq_num = 0

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
            s.sendto(seq_num.to_bytes(payload_size, byteorder='big'), (dst, dport))
            # Save log to the .csv file
            csv_writer.writerow({'seq_num': seq_num, 't_timestamp': timestamp})
            # Increase the sequence number
            seq_num += 1
            # Increse the burst counter
            brst_count += 1
            # Remove tokens from the bucket
            token_bucket -= payload_size
            # If the sequence number needs more bytes, raise exception
            if math.ceil(seq_num.bit_length() / 8) > payload_size:
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
            data, address = s.recvfrom(2048)
            # Get timestamp
            timestamp = time.time()
            # Get source address
            _, pkt_sport = address

            # Only accept packets from the expected source
            if pkt_sport == sport:
                # Parse sequence number
                seq_num = int.from_bytes(data, byteorder='big')
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
                  max_burst_size=TCP_MAX_BURST_SIZE,
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
        max_burst_size (int, optional): Maximum number of chunks that can be sent to the TCP output at once.
                                        Defaults to TCP_MAX_BURST_SIZE.
        out_csv (str, optional): Log of sent packets with timestamps. Defaults to 'send.csv'.

    Note:
        - If ``max_burst_size`` is set to ``0``, then no rate limiting is performed on top of
          TCP. Otherwise, rate limiting is performed with the given ``rate`` and ``max_burst_size``.
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
    assert max_burst_size > 0 # The burst size must be at least one chunk.
    assert isinstance(sport, int) and sport > 0 and sport < 2**16 # Check valid port number
    assert isinstance(dport, int) and dport > 0 and dport < 2**16 # Check valid port number
    assert isinstance(tos, int) and tos >= 0 and tos < 2**8 # Check valid ToS value
    assert (isinstance(duration, float) or isinstance(duration, int)) and duration >= 0 # Duration must not be negative
    assert isinstance(payload_size, int) and payload_size > 0 and payload_size <= TCP_MAX_PAYLOAD # Check valid payload size
    assert isinstance(max_burst_size, int) and max_burst_size >= 0

    # Compute tot_bytes
    if send_size > 0:
        tot_bytes = send_size
    else:
        tot_bytes = math.ceil(rate*duration)

    # Open .csv file
    output = open(out_csv, 'w', newline='')
    # Fields of the .csv
    fields = ['t_timestamp']
    # CSV writer
    csv_writer = csv.DictWriter(output, fieldnames=fields)
    # Write header
    csv_writer.writeheader()
    # Save tot_bytes as first line
    csv_writer.writerow({'t_timestamp': tot_bytes})

    # Open socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_IP, socket.IP_TOS, tos)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_TCP, socket.TCP_MAXSEG, payload_size)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.bind(('', sport))

    # Save start time
    startTime = lastTime = time.time()

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
        _payload = b'\x01' + bytes(payload_size - 1)
        bytes_to_send = min(tot_bytes, payload_size)
        # If there are actual data to send
        if bytes_to_send > 0:
            # Create payload
            if bytes_to_send != payload_size:
                payload = b'\x01' + bytes(bytes_to_send - 1)
            else:
                payload = _payload
            # Update timeouts
            if endTime is not None:
                s.settimeout(max(endTime - time.time(), 0))
            else:
                s.setblocking(True)

            try:
                # Send packet
                sent = s.send(payload)
                # Get timestamp
                timestamp = time.time()
            # If timeout expired
            except socket.timeout:
                # Exit loop
                break

            # Save log to the .csv file
            csv_writer.writerow({'t_timestamp': timestamp})

            # Remove bytes_to_send from tot_bytes
            tot_bytes -= sent

        # Break if all the data were sent
        if tot_bytes <= 0:
            break
        
        # Break if duration expired
        if endTime is not None:
            # Get current time
            currentTime = time.time()
            if currentTime >= endTime:
                break

    # Close socket
    s.close()
    # Close .csv file
    output.close()


def recv_tcp_flow(sport=5000,
                  dport=5001,
                  duration=10,
                  out_csv='recv.csv',
                  **kwargs):
    """TCP Receiving function.

    Args:
        sport (int, optional): Source port of the flow. Defaults to 5000.
        dport (int, optional): Port to listen on. Defaults to 5001.
        duration (float, optional): Listening time in seconds. Defaults to 10.
        out_timestamp_csv (str, optional): Log of received packets with timestamps. 
                                           Defaults to 'r_timestamps.csv'.
    """
    # Sanity checks
    assert isinstance(sport, int) and sport > 0 and sport < 2**16 # Check valid port number
    assert isinstance(dport, int) and dport > 0 and dport < 2**16 # Check valid port number
    assert (isinstance(duration, float) or isinstance(duration, int)) and duration >= 0 # Duration must be positive

    # Initialize received bytes to zero
    recv_bytes = 0

    # Open .csv file
    output = open(out_csv, 'w', newline='')
    # Fields of the .csv
    fields = ['r_timestamp']
    # CSV writer
    csv_writer = csv.DictWriter(output, fieldnames=fields)
    # Write header
    csv_writer.writeheader()

    # Open socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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
                # Close .csv file
                output.close()
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
            # Close .csv file
            output.close()
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
            # Get timestamp
            timestamp = time.time()
            # Break if remote endpoint closed connection
            if not data:
                break
        # If timeout expired
        except socket.timeout:
            break

        # Get number of timestamp requests (\x01)
        n_timestamps = data.count(b'\x01')

        for _ in range(n_timestamps):
            # Save log to the .csv file
            csv_writer.writerow({'r_timestamp': timestamp})

        # Get data length
        recv_bytes += len(data)
    
    # Save recv_bytes as last line
    csv_writer.writerow({'r_timestamp': recv_bytes})
    # Close .csv file
    output.close()
    # Close connection
    conn.close()
    # Close socket
    s.close()
