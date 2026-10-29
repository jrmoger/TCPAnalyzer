import struct

protocol_offset = 23

def parse_packet_header(header) -> tuple[int, int, int, int]:
    '''
    returns values of packet header in a tuple: (ts_sec, ts_usec, incl_len, orig_len)
    '''
    ts_sec, ts_usec, incl_len, orig_len = struct.unpack('IIII', header)
    return (ts_sec, ts_usec, incl_len, orig_len)

def get_relative_time(ts_sec:int, ts_usec:int, t0:float) -> float:
    '''
    returns time relative to t0
    '''
    ts_abs = ts_sec + ts_usec*10**-6
    return ts_abs - t0

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
ts_sec, ts_usec, incl_len, orig_len = struct.unpack('IIII', packet_header)

print(ts_sec, ts_usec, incl_len, orig_len)
ts_abs = ts_sec + ts_usec * 10**-6
ts_0 = ts_abs
ts = ts_abs - ts_0

print(f"{ts:.6f}" )
print(f"{ts_abs:.6f}" )

packets = [] # store packet tuples: (timestamp, packet_data)
n = 0

# packet_header = f.read(orig_len)
# protocol_val = struct.unpack('B', packet_header[protocol_offset:protocol_offset+1])[0]

# print(protocol_val)
# # if protocol_val == 6:
# #     # is tcp

while True:
    print("packet num:", n)
    packet_data = f.read(orig_len)
    # print(packet_data)
    protocol_val = struct.unpack('B', packet_data[protocol_offset:protocol_offset+1])[0]
    print("protocol_val:",protocol_val)
    if protocol_val == 6:
        # packets.append((ts, packet_data))
        packets.append(ts)
    else:
        print("skipping packet")

    packet_header = f.read(16)
    if len(packet_header) < 16:
        break
    ts_sec, ts_usec, incl_len, orig_len = struct.unpack('IIII', packet_header)
    ts = get_relative_time(ts_sec, ts_usec, ts_0)
    n+=1


print(packets)