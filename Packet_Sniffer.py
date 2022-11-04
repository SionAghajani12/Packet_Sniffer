import socket
import struct
import textwrap

Tab_1 = '\t - '
Tab_2 = '\t\t - '
Tab_3 = '\t\t\t - '
Tab_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65536)
        destination_mac, source_mac, eth_proto, data = ethernet(raw_data)
        print('\nEthernet Frame: ')
        print("Destination: {}, Source: {}, Protocol: {}".format(destination_mac, source_mac, eth_proto ))

        if eth_proto == 8:
            (version, header, ttl, proto, src, target, data) = ipv4_packet(data)
            print(Tab_1 + 'IPv4 Packet: ')
            print(Tab_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header, ttl))
            print(Tab_2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print(Tab_1 + 'ICMP Packet: ')
                print(Tab_2 + 'Type: {}, code: {}, checksum: {}'.format(icmp_type, code, checksum))
                print(Tab_2 + 'Data: ')
                print(format_multi_line_data(DATA_TAB_3, data))
            
            elif proto == 6:
                src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin , data = tcp_segment(data)
                print(Tab_1 + 'TCP Segment: ')
                print(Tab_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                print(Tab_2 + 'Sequence: {}, Acknowledgment: {}'.format(sequence, acknowledgment))
                print(Tab_2 + 'Flags: ')
                print(Tab_3 + 'URG: {}, ACK: {}, PSH {}, RST: {}, SYN: {}, FIN:{}'.format(flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_syn))
                print(Tab_2 + 'Data: ')
                print(format_multi_line_data(DATA_TAB_3, data))

            elif proto == 17:
                src_port, dest_port, length, data = udp_segment(data)
                print(Tab_1 + 'UDP Segment: ')
                print(Tab_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, length))
                print(Tab_2 + 'Data: ')
                print(format_multi_line_data(DATA_TAB_3, data))


            

#Ethernet Frame
def ethernet(data):
    destination_mac, source_mac, protocol = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_address(destination_mac), get_mac_address(source_mac), socket.htons(protocol), data[14:]

#Getting proper Mac Address
def get_mac_address(add_bytes):
    bytes_string = map('{:02x}'.format, add_bytes)
    return ':'.join(bytes_string).upper()

#Unpack IPv4 packet
def ipv4_packet(data):
    version_lentgh = data[0]
    version = version_lentgh >> 4
    header = (version_lentgh & 15) * 4
    ttl, proto, src, target =  struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header, ttl, proto, ipv4(src), ipv4(target), data[header:]

#Returns properly formated IPv4 address
def ipv4(addr):
    return '.'.join(map(str, addr ))

# Unpacked ICMP packet
def icmp_packet(data):
    icmp_type, code, checksum  = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

#Unpack TCP packet
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 32) >> 4
    flag_psh = (offset_reserved_flags & 32) >> 3
    flag_rst = (offset_reserved_flags & 32) >> 2
    flag_syn = (offset_reserved_flags & 32) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

#Unpack UDP segment
def udp_segment(data):
    src_port,dest_port,size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port,size,data[8:]

#format multi-line data
def format_multi_line_data(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string,bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string,size)])            

main()