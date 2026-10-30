import struct

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

# packet tuple indices (ADDRESS, TS, SEQ, ACK, OFFSET, FLAGS, WSIZE)
ADDRESS_TUPLE = 0
TIMESTAMP = 1
SEQ_NUM = 2
ACK_NUM = 3
DATA_OFFSET = 4
FLAGS = 5
WINDOW_SIZE = 6

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

f = open("sample-capture-file.cap", "rb")

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

print(magic, version_major, version_minor, thiszone,
      sigfigs, snaplen, network, endian)

packet_header = f.read(16)
ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian+'IIII', packet_header)

print(ts_sec, ts_usec, incl_len, orig_len)
ts_abs = ts_sec + (ts_usec * 10**-6)
ts_0 = ts_abs
ts = ts_abs - ts_0

print(f"{ts:.6f}" )
print(f"{ts_abs:.6f}" )

connection_dict = {} # connection dictionary
n = 1 # packet number

while True:
    print("packet num:", n)
    packet_data = f.read(orig_len)
    protocol_val = struct.unpack('B', packet_data[protocol_offset:protocol_offset+1])[0]
    if protocol_val == 6:
        parsed_packet = parse_packet(packet_data, ts)
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
    ts_sec, ts_usec, incl_len, orig_len = struct.unpack('IIII', packet_header)
    ts = get_relative_time(ts_sec, ts_usec, ts_0)
    n+=1


for connection in connection_dict:
    syn_count = 0
    fin_count = 0
    start_time = 0
    end_time = 0
    rst = 0
    for packet in connection_dict[connection]:
        # print(packet)
        if packet[FLAGS][RST] == 1:
            rst = 1

        if packet[FLAGS][SYN] == 1:
            syn_count += 1
            if start_time == 0 or packet[TIMESTAMP] < start_time:
                start_time = packet[TIMESTAMP]
        elif packet[FLAGS][FIN] == 1:
            fin_count += 1
            if packet[TIMESTAMP] > end_time:
                end_time = packet[TIMESTAMP]
    if syn_count < 1 or fin_count < 1:
        print(f"incomplete connection {connection}: s{syn_count}f{fin_count}")
        continue
    
    print(f"complete connection {connection}: s{syn_count}f{fin_count}")
    print(f"\tduration: {(end_time - start_time):.6f}")


f.close()
# print(connection_dict)