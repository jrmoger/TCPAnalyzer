import struct
import sys

# indices
protocol_offset = 23
ip_header_start = 14
src_ip_offset = ip_header_start + 12
dst_ip_offset = ip_header_start + 16
tcp_header_start = 34
tcp_dst_offset = tcp_header_start + 2
tcp_seq_offset = tcp_header_start + 4
tcp_ack_offset = tcp_header_start + 8
tcp_flag_offset = tcp_header_start + 12
tcp_window_offset = tcp_header_start + 14



# flag tuple indices (SYN, ACK, FIN, RST)
SYN = 0
ACK = 1
FIN = 2
RST = 3

# packet tuple indices (ADDRESS, TS, SEQ, ACK, OFFSET, FLAGS, WSIZE, PACKET)
ADDRESS_TUPLE = 0
TIMESTAMP = 1
SEQ_NUM = 2
ACK_NUM = 3
DATA_OFFSET = 4
FLAGS = 5
WINDOW_SIZE = 6
PACKET_DATA = 7
PAYLOAD_LEN = 8

def get_relative_time(ts_sec:int, ts_usec:int, t0:float) -> float:
    '''
    returns time relative to t0
    '''
    ts_abs = ts_sec + (ts_usec*10**-6)
    return ts_abs - t0

def parse_packet(packet: bytes, ts: float):
    '''
    returns tcp information: ((4-tuple), seq_num, ack_num, data_offset, (flags), window_size)
    '''
    ip_hdr_len = (packet[ip_header_start] & 0x0F) * 4   # IHL, in bytes
    tcp_start = ip_header_start + ip_hdr_len            # TCP header follows the IP header

    src_ip = '.'.join(str(b) for b in packet[src_ip_offset:src_ip_offset + 4])
    dst_ip = '.'.join(str(b) for b in packet[dst_ip_offset:dst_ip_offset + 4])

    (src_port, dst_port, seq_num, ack_num,
     offset_byte, flag_byte, window_size) = struct.unpack('>HHIIBBH', packet[tcp_start:tcp_start + 16])

    data_offset = ((offset_byte & 0xF0) >> 4) * 4   # TCP header length in bytes
    syn = (flag_byte & 0x02) >> 1
    ack = (flag_byte & 0x10) >> 4
    fin = flag_byte & 0x01
    rst = (flag_byte & 0x04) >> 2

    address = (src_ip, src_port, dst_ip, dst_port)
    return (address, ts, seq_num, ack_num, data_offset, (syn, ack, fin, rst), window_size)

def get_key(ip):
    '''
    returns lexicographically sorted key of given 4-tuple
    '''
    return ip if (ip[0], ip[1]) < (ip[2], ip[3]) else (ip[2], ip[3], ip[0], ip[1])

def get_payload_len(packet: bytes) -> int:
    # IP header length from IHL (low nibble of first IP byte), in bytes
    ip_hdr_len = (packet[ip_header_start] & 0x0F) * 4

    # IP total length (big-endian 16 bit at IP bytes 2-3)
    ip_total_len = struct.unpack('>H', packet[ip_header_start + 2:ip_header_start + 4])[0]


    tcp_start = ip_header_start + ip_hdr_len
    tcp_hdr_len = ((packet[tcp_start + 12] & 0xF0) >> 4) * 4

    return ip_total_len - ip_hdr_len - tcp_hdr_len

def find_source(packets):
    '''
    find the source endpoint from a list of packets
    '''
    for p in packets:
        if p[FLAGS][SYN] == 1 and p[FLAGS][ACK] == 0:
            return p[ADDRESS_TUPLE]
    return packets[0][ADDRESS_TUPLE]

def calculate_rtt_samples(packets):
    '''
    method 1 (top down scan)
    for each data packet, the first later ACK from the other endpoint
    whose ACK numer equals seq + payload length gives one RTT sample.
    Data Packets with no matching ACK produce no sample.
    '''
    waiting = {}
    samples = []

    for packet in packets:
        address = packet[ADDRESS_TUPLE]
        ts = packet[TIMESTAMP]

        if packet[FLAGS][ACK] == 1:
            src_ip, src_port, dst_ip, dst_port = address
            data_sender = (dst_ip, dst_port, src_ip, src_port)
            for sent_ts in waiting.pop((data_sender, packet[ACK_NUM]), []):
                samples.append(ts - sent_ts)

        if packet[PAYLOAD_LEN] > 0:
            expected_ack = (packet[SEQ_NUM] + packet[PAYLOAD_LEN]) % 2**32
            waiting.setdefault((address, expected_ack), []).append(ts)

    return samples

def main(path): 
    try:   
        f = open(path, "rb")
    except:
        print("Invalid path")
        return

    global_header = f.read(24)

    magic_le = struct.unpack('<I', global_header[:4])[0]
    if magic_le == 0xa1b2c3d4:
        endian = '<'
    elif magic_le == 0xd4c3b2a1:
        endian = '>'
    else:
        raise ValueError("Not a pcap file (unrecognized magic number)")

    (magic, version_major, version_minor, thiszone,
    sigfigs, snaplen, network) = struct.unpack(endian + 'IHHiIII', global_header)

    connection_dict = {}
    ts_0 = None
    while True:
        packet_header = f.read(16)
        if len(packet_header) < 16:
            break
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + 'IIII', packet_header)
        if ts_0 is None:
            ts_0 = (ts_sec, ts_usec)
        ts = (ts_sec - ts_0[0]) + (ts_usec - ts_0[1]) / 1e6   # integer subtraction keeps precision

        packet_data = f.read(incl_len)
        # keep only IPv4 (EtherType 0x0800) TCP (protocol 6) frames
        if len(packet_data) < 54 or packet_data[12:14] != b'\x08\x00' or packet_data[23] != 6:
            continue

        parsed = parse_packet(packet_data, ts) + (packet_data, get_payload_len(packet_data))
        connection_dict.setdefault(get_key(parsed[ADDRESS_TUPLE]), []).append(parsed)

    f.close()

    print(f"A) Total number of connections: {len(connection_dict)}\n")
    print("B) Connections' details:")

    rst_count = complete_count = open_count = before_count = 0
    durations, packets_sent, window_sizes, rtt_values = [], [], [], []

    rst_count = complete_count = open_count = before_count = 0
    durations, packets_sent, window_sizes, rtt_values = [], [], [], []



    for connection_num, packets in enumerate(connection_dict.values(), start=1):
        source = find_source(packets)
        syn_count = fin_count = rst = 0
        start_time = None
        end_time = 0
        src_dst_count = dst_src_count = 0
        src_dst_bytes = dst_src_bytes = 0

        for p in packets:
            if p[FLAGS][RST]:
                rst = 1
            if p[FLAGS][SYN]:                  # SYN and SYN+ACK both count as SYN
                syn_count += 1
                if start_time is None or p[TIMESTAMP] < start_time:
                    start_time = p[TIMESTAMP]
            if p[FLAGS][FIN]:                  # separate if, so SYN+FIN counts for both
                fin_count += 1
                end_time = max(end_time, p[TIMESTAMP])
            if p[ADDRESS_TUPLE] == source:
                src_dst_count += 1
                src_dst_bytes += p[PAYLOAD_LEN]
            else:
                dst_src_count += 1
                dst_src_bytes += p[PAYLOAD_LEN]

        is_reset = rst == 1
        is_complete = syn_count >= 1 and fin_count >= 1 and not is_reset

        if is_reset:
            rst_count += 1
        if packets[0][FLAGS][SYN] == 0:        # first segment is not a SYN
            before_count += 1
        has_data_after_fin = any(p[PAYLOAD_LEN] > 0 and p[TIMESTAMP] > end_time for p in packets)
        if not is_reset and (fin_count == 0 or has_data_after_fin):
            open_count += 1

        status = "R" if is_reset else f"S{syn_count}F{fin_count}"

        if is_complete:
            complete_count += 1
            durations.append(end_time - start_time) # type: ignore
            packets_sent.append(len(packets))
            window_sizes.extend(p[WINDOW_SIZE] for p in packets)
            samples = calculate_rtt_samples(packets)
            if samples:
                rtt_values.append(sum(samples) / len(samples))

        if connection_num > 1:
            print("\n+++++++++++++++++++++++++++++++++\n")
        print(f"Connection {connection_num}:")
        print(f"Source Address: {source[0]}")
        print(f"Destination address: {source[2]}")
        print(f"Source Port: {source[1]}")
        print(f"Destination Port: {source[3]}")
        print(f"Status: {status}")
        if is_complete:
            print(f"Start time: {start_time:.6f}")
            print(f"End Time: {end_time:.6f}")
            print(f"Duration: {end_time - start_time:.6f}")
            print(f"Number of packets sent from Source to Destination: {src_dst_count}")
            print(f"Number of packets sent from Destination to Source: {dst_src_count}")
            print(f"Total number of packets: {len(packets)}")
            print(f"Number of data bytes sent from Source to Destination: {src_dst_bytes}")
            print(f"Number of data bytes sent from Destination to Source: {dst_src_bytes}")
            print(f"Total number of data bytes: {src_dst_bytes + dst_src_bytes}")


    print("\n\n------------------------------\n\n")

    print("\nC) General")
    print(f"The total number of complete TCP connections: {complete_count}")
    print(f"Number of reset TCP connections: {rst_count}")
    print(f"Number of TCP connections that were still open when the trace capture ended: {open_count}")
    print(f"Number of TCP connections established before the capture started: {before_count}")


    print("\nD) Complete TCP connections:")
    print_stats("time duration", durations)
    print_stats("RTT value", rtt_values)
    print_stats("number of packets including both send/received", packets_sent,
                minmax_fmt="d", mean_fmt=".2f")
    print_stats("receive window size including both send/received", window_sizes,
                minmax_fmt="d", mean_fmt=".2f")


def print_stats(name, values, minmax_fmt=".6f", mean_fmt=".6f"):
    '''prints the min, mean and max of values, or N/A when the list is empty'''
    if not values:
        for label in ("Minimum", "Mean", "Maximum"):
            print(f"{label} {name}: N/A")
        return
    print(f"Minimum {name}: {min(values):{minmax_fmt}}")
    print(f"Mean {name}: {sum(values) / len(values):{mean_fmt}}")
    print(f"Maximum {name}: {max(values):{minmax_fmt}}\n")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Invalid command")
        print("Usage: TCPAnalyzer.py [path to pcap file]")
    else:
        path = sys.argv[1]
        main(path)