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

def parse_packet(packet:bytes, ts:float) -> tuple[tuple[str, int, str, int], float, int, int, int, tuple[int, int, int, int], int]:
    '''
    returns tcp information: (4-tuple(), seq_num, ack_num, data_offset, flags(), window_size)
    '''
    buffer1 = packet[src_ip_offset:src_ip_offset+4]
    buffer2 = packet[dst_ip_offset:dst_ip_offset+4]
    src_addr = struct.unpack('BBBB', buffer1)
    dst_addr = struct.unpack('BBBB', buffer2)
    src_ip = str(src_addr[0])+'.'+str(src_addr[1])+'.'+str(src_addr[2])+'.'+str(src_addr[3])
    dst_ip = str(dst_addr[0])+'.'+str(dst_addr[1])+'.'+str(dst_addr[2])+'.'+str(dst_addr[3])

    buffer3 = int.from_bytes(packet[tcp_flag_offset+1:tcp_flag_offset+2])
    buffer4 = packet[tcp_header_start:tcp_window_offset+2]

    (src_port, dst_port, seq_num, ack_num, data_offset, 
     window_size) = struct.unpack('>HHIIBxH', buffer4)
    data_offset = int((data_offset & 0b11110000) >> 4) * 4 # get high 4 bits and mulitply by 4

    syn = (buffer3 & 0x02) >> 1
    ack = (buffer3 & 0x10) >> 4
    fin = (buffer3 & 0x01)
    rst = (buffer3 & 0x04) >> 2
    flags = (syn, ack, fin, rst)
    address = (src_ip, src_port, dst_ip, dst_port)
    return (address, ts, seq_num, ack_num, data_offset, flags, window_size)

def get_key(ip:tuple[str, int, str, int]) -> tuple[str, int, str, int]:
    '''
    converts 4-tuple into a lexicographically sorted key
    '''
    if ip[0] < ip[2]:
        return ip
    else:
        return (ip[2], ip[3], ip[0], ip[1])

def get_payload_len(packet: bytes) -> int:
    # IP header length from IHL (low nibble of first IP byte), in bytes
    ip_hdr_len = (packet[ip_header_start] & 0x0F) * 4

    # IP total length (big-endian 16 bit at IP bytes 2-3)
    ip_total_len = struct.unpack('>H', packet[ip_header_start + 2:ip_header_start + 4])[0]


    tcp_start = ip_header_start + ip_hdr_len
    tcp_hdr_len = ((packet[tcp_start + 12] & 0xF0) >> 4) * 4

    return ip_total_len - ip_hdr_len - tcp_hdr_len

def calculate_rtt_samples(packets: list) -> list[float]:
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

    packet_header = f.read(16)
    ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian+'IIII', packet_header)

    ts_abs = ts_sec + (ts_usec * 10**-6)
    ts_0 = ts_abs
    ts = ts_abs - ts_0


    connection_dict = {} # connection dictionary
    n = 1 # packet number

    while True:
        packet_data = f.read(incl_len)
        protocol_val = struct.unpack('B', packet_data[protocol_offset:protocol_offset+1])[0]
        if protocol_val == 6:
            parsed_packet = parse_packet(packet_data, ts)
            parsed_packet = parsed_packet + (packet_data, get_payload_len(packet_data))
            key = get_key(parsed_packet[ADDRESS_TUPLE])
            if key in connection_dict:
                connection_dict[key].append(parsed_packet)
            else:
                connection_dict[key] = [parsed_packet]
        else:
            print("skipping packet")

        packet_header = f.read(16)
        if len(packet_header) < 16:
            break
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian+'IIII', packet_header)
        ts = get_relative_time(ts_sec, ts_usec, ts_0)
        n+=1

    f.close()

    print(f"Total number of connections: {len(connection_dict)}")
    print("\n\n------------------------------\n\n")

    rst_count = 0
    connection_num = 0
    complete_count = 0
    incomplete_count = 0
    no_start_count = 0
    durations = []
    rtt_values = []
    packets_sent = []
    window_sizes = []

    for connection in connection_dict:
        syn_count = 0
        fin_count = 0
        start_time = None
        end_time = 0
        rst = 0
        source = None
        packet_count = 0
        src_dst_count = 0
        dst_src_count = 0
        src_dst_byte_count = 0
        dst_src_byte_count = 0
        byte_count = 0
        connection_num += 1
        status = 0

        for packet in connection_dict[connection]:  # iterate over each connection
            address = packet[ADDRESS_TUPLE]
            if packet[FLAGS][RST] == 1:
                rst = 1

            if packet[FLAGS][SYN] == 1: # iterate over each packet in a connection
                syn_count += 1
                if start_time is None or packet[TIMESTAMP] < start_time:
                    start_time = packet[TIMESTAMP]
                if source is None:        # since get_key() sorts the endpoints, record first SYN as source
                    source = address
            if packet[FLAGS][FIN] == 1:
                fin_count += 1
                if packet[TIMESTAMP] > end_time:
                    end_time = packet[TIMESTAMP]
            if address == source:
                src_dst_count += 1
                src_dst_byte_count += packet[PAYLOAD_LEN]
            else:
                dst_src_count += 1
                dst_src_byte_count += packet[PAYLOAD_LEN]
            packet_count += 1
            byte_count += packet[PAYLOAD_LEN]


        if syn_count < 1 or fin_count < 1:
            status = 1

        if rst == 1:
            rst_count += 1
            status = 2

        duration = end_time - start_time # type: ignore

        if source is None:
            source = ("error", "error", "error", "error")

        print(f"Connection {connection_num}:")
        print(f"Source address: {source[0]}")
        print(f"Destination address: {source[2]}")
        print(f"Source port: {source[1]}")
        print(f"Destination port: {source[3]}")
        if status == 2:
            print(f"Status: R")
        else:
            print(f"Status: S{syn_count}F{fin_count}")

        if status == 0:
            durations.append(duration)
            packets_sent.append(packet_count)
            window_sizes.extend(packet[WINDOW_SIZE] for packet in connection_dict[connection]) # record window sizes of complete connections
            complete_count += 1
            samples = calculate_rtt_samples(connection_dict[connection])
            if samples:
                rtt_values.append(sum(samples) / len(samples))
            
            print(f"Start time: {start_time:.6f}")
            print(f"End time: {end_time:.6f}")
            print(f"Duration: {duration:.6f}")
            print(f"Number of packets sent from Source to Destination: {src_dst_count}")
            print(f"Number of packets sent from Destination to Source: {dst_src_count}")
            print(f"Total number of packets: {packet_count}")
            print(f"Number of data bytes sent from Source to Destination: {src_dst_byte_count}")
            print(f"Number of data bytes sent from Destination to Source: {dst_src_byte_count}")
            print(f"Total number of data bytes: {byte_count}")
        print("\n\t\t----------\n")

    print("\n\n------------------------------\n\n")

    print(f"Total number of TCP connections: {complete_count}")
    print(f"Number of reset TCP connections: {rst_count}")
    print(f"Number of TCP connections that were still open when the tract capture ended: {incomplete_count}")
    print(f"Number of TCP connections established before the capture started: {no_start_count}")

    print(f"\nMinimum time duration: {min(durations):.6f}")
    print(f"Mean time duration: {(sum(durations) / len(durations)):.6f}")
    print(f"Maximum time duration: {max(durations):.6f}")

    print(f"\nMinimum RTT value: {min(rtt_values):.6f}")
    print(f"Mean RTT value: {(sum(rtt_values) / len(rtt_values)):.6f}")
    print(f"Maximum RTT value: {max(rtt_values):.6f}")

    print(f"\nMinimum number of packets including send/recieved: {min(packets_sent)}")
    print(f"Mean number of packets including send/recieved: {sum(packets_sent) / len(packets_sent)}")
    print(f"Maximum number of packets including send/recieved: {max(packets_sent)}")

    print(f"\nMinimum receive window size including both send/received: {min(window_sizes)}")
    print(f"Mean receive window size including both send/received: {(sum(window_sizes) / len(window_sizes)):.2f}")
    print(f"Maximum receive window size including both send/received: {max(window_sizes)}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Invalid command")
        print("Usage: TCPAnalyzer.py [path to pcap file]")
    else:
        path = sys.argv[1]
        main(path)