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

SYN = 0
ACK = 1
FIN = 2
RST = 3

SRC_PORT = 0
DST_PORT = 1
SEQ_NUM = 2
ACK_NUM = 3
DATA_OFFSET = 4
FLAGS = 5
WINDOW_SIZE = 6


# flags = (SYN, ACK, FIN, RST)

def parse_packet_header(header:bytes) -> tuple[int, int, int, int]:
    '''
    returns values of packet header in a tuple: (ts_sec, ts_usec, incl_len, orig_len)
    '''
    ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian+'IIII', header)
    return (ts_sec, ts_usec, incl_len, orig_len)

def get_relative_time(ts_sec:int, ts_usec:int, t0:float) -> float:
    '''
    returns time relative to t0
    '''
    ts_abs = ts_sec + ts_usec*10**-6
    return ts_abs - t0

def get_ip(packet:bytes) -> tuple[str, str]:
    buffer1 = packet[src_ip_offset:src_ip_offset+4]
    buffer2 = packet[dst_ip_offset:dst_ip_offset+4]
    src_addr = struct.unpack('BBBB', buffer1)
    dst_addr = struct.unpack('BBBB', buffer2)
    src_ip = str(src_addr[0])+'.'+str(src_addr[1])+'.'+str(src_addr[2])+'.'+str(src_addr[3])
    dst_ip = str(dst_addr[0])+'.'+str(dst_addr[1])+'.'+str(dst_addr[2])+'.'+str(dst_addr[3])
    return (src_ip, dst_ip)

def get_tcp(packet:bytes) -> tuple[int, int, int, int, int, tuple[int, int, int, int], int]:
    '''
    returns tcp information: (src_port, dst_port, seq_num, ack_num, data_offset, flags(), window_size)
    '''

    buffer3 = int.from_bytes(packet[tcp_flag_offset+1:tcp_flag_offset+2])
    buffer5 = packet[tcp_header_start:tcp_window_offset+2]

    (src_port, dst_port, seq_num, ack_num, data_offset, 
     window_size) = struct.unpack('>HHIIBxH', buffer5)
    data_offset = int((data_offset & 0b11110000) >> 4) * 4


    syn = (buffer3 & 0x02) >> 1
    ack = (buffer3 & 0x10) >> 4
    fin = (buffer3 & 0x01)
    rst = (buffer3 & 0x04) >> 2
    flags = (syn, ack, fin, rst)

    return (src_port, dst_port, seq_num, ack_num, data_offset, flags, window_size)

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
ts_abs = ts_sec + ts_usec * 10**-6
ts_0 = ts_abs
ts = ts_abs - ts_0

print(f"{ts:.6f}" )
print(f"{ts_abs:.6f}" )

connection_dict = {}
packets = [] # store packet tuples: (timestamp, ...)
n = 0 # packet number

# packet_header = f.read(orig_len)
# protocol_val = struct.unpack('B', packet_header[protocol_offset:protocol_offset+1])[0]

# print(protocol_val)
# # if protocol_val == 6:
# #     # is tcp

while True and n < 2:
    print("packet num:", n)
    packet_data = f.read(orig_len)
    # print(packet_data)
    protocol_val = struct.unpack('B', packet_data[protocol_offset:protocol_offset+1])[0]
    print("protocol_val:", protocol_val)
    if protocol_val == 6:
        packets.append((ts, packet_data))
        ip = get_ip(packet_data)
        tcp = get_tcp(packet_data)
        print("ts:", ts)
        print("ip:", ip)
        print("tcp:", tcp)
        # packets.append(ts)
    else:
        print("skipping packet")

    packet_header = f.read(16)
    if len(packet_header) < 16:
        break
    ts_sec, ts_usec, incl_len, orig_len = struct.unpack('IIII', packet_header)
    ts = get_relative_time(ts_sec, ts_usec, ts_0)
    n+=1


# print(packets)