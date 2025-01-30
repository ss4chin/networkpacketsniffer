import socket
import struct
import textwrap

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t - '
DATA_TAB_2 = '\t\t - '
DATA_TAB_3 = '\t\t\t - '
DATA_TAB_4 = '\t\t\t\t - '

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, add = conn.recvfrom(65535)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print("\n Ethernet Frame: ")
        print("Destination: {}, Source: {}, Protocol: {}".format(dest_mac, src_mac, eth_proto))

        # 8 for IPV4
        if eth_proto == 8:
            (version, header_length, ttl, protocol, src, target, data) = ipv4_packet(data)
            print(TAB_1 + 'IPV4 Packet: ')
            print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}, '.format(version, header_length, ttl))
            print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(protocol, src, target))

            #ICMP
            if protocol == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print(TAB_1 + 'ICMP Packet: ')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {}, '.format(icmp_type, code, checksum))
                print(TAB_2 + 'Data: ')
                print(format_multiline_data(DATA_TAB_3, data))

            #TCP
            elif protocol == 6:
                (src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin) = tcp_segment(data)
                print(TAB_1 +'TCP Segment: ')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}, '.format(src_port, dest_port))
                print(TAB_2 + 'Sequence: {}, Acknowledgement: {}'.format(sequence, acknowledgement))
                print(TAB_2 + 'Flags: ')
                print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST" {}, SYN:{}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))

            #UDP 
            elif protocol == 17:
                src_port, dest_port, length, data = udp_segment(data)
                print(TAB_1 + 'UDP Segment: ')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}, '.format(src_port, dest_port, length))

            #Other
            else:
                print(TAB_1 + 'Data: ')
                print(format_multiline_data(DATA_TAB_2, data))
        else:
            print('Data:')
            print(format_multiline_data(DATA_TAB_1,))      
       
# Unpacking Ethernet Frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14] )
    return get_mac_add(dest_mac), get_mac_add(src_mac), socket.htons(proto), data[:14]

# Returning resolved (formatted) MAC Addresses (22:22:22:22)
def get_mac_add(bytes_add):
    bytes_str = map('{:02x}'.format, bytes_add)
    mac_add = ':'.join(bytes_str).upper()
    return mac_add

# unpack ipv4 packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, protocol, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, protocol, src, target, ipv4(src), ipv4(target), data[header_length:]

#returns proper formatted ipv4 address
def ipv4(add):
    return '.'.join(map(str, add,))

# Unpacking ICMP packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# Unpacking TCP packet
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

#Unpack UDP segment
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

# multiline data formatting
def format_multiline_data(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{0.2x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
        return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])
    












