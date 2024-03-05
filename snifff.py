import socket
import struct

def main():
    # Create a raw socket and bind it to the public interface
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    
    while True:
        raw_data, addr = connection.recvfrom(65535)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        
        print('\nEthernet Frame:')
        print(f'Destination MAC: {dest_mac}, Source MAC: {src_mac}, Protocol: {eth_proto}')
        
        # IP packets
        if eth_proto == 8:
            version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
            print(f'IPv4 Packet:')
            print(f' - Version: {version}, Header Length: {header_length}, TTL: {ttl}')
            print(f' - Protocol: {proto}, Source: {src}, Target: {target}')
            
            # ICMP
            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print('ICMP Packet:')
                print(f' - Type: {icmp_type}, Code: {code}, Checksum: {checksum}')
                print(f' - Data: {data}')
            
            # TCP
            elif proto == 6:
                src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(data)
                print('TCP Segment:')
                print(f' - Source Port: {src_port}, Destination Port: {dest_port}')
                print(f' - Sequence: {sequence}, Acknowledgment: {acknowledgment}')
                print(' - Flags:')
                print(f'   - URG: {flag_urg}, ACK: {flag_ack}, PSH: {flag_psh}, RST: {flag_rst}, SYN: {flag_syn}, FIN: {flag_fin}')
                print(f' - Data: {data}')
            
            # UDP
            elif proto == 17:
                src_port, dest_port, length, data = udp_segment(data)
                print('UDP Segment:')
                print(f' - Source Port: {src_port}, Destination Port: {dest_port}, Length: {length}')
                print(f' - Data: {data}')
            
            # Other IPv4
            else:
                print('Other IPv4 Data:')
                print(data)

        # Other Ethernet
        else:
            print('Other Ethernet Data:')
            print(data)


# Unpack Ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return format_mac(dest_mac), format_mac(src_mac), socket.htons(proto), data[14:]


# Format MAC address
def format_mac(mac):
    mac_str = ':'.join(['{:02x}'.format(b) for b in mac])
    return mac_str


# Unpack IPv4 packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, format_ip(src), format_ip(target), data[header_length:]


# Format IP address
def format_ip(addr):
    return '.'.join(map(str, addr))


# Unpack ICMP packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]


# Unpack TCP segment
def tcp_segment(data):
    src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flags = struct.unpack('! H', data[14:16])[0]
    flag_urg = (flags & 32) >> 5
    flag_ack = (flags & 16) >> 4
    flag_psh = (flags & 8) >> 3
    flag_rst = (flags & 4) >> 2
    flag_syn = (flags & 2) >> 1
    flag_fin = flags & 1
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]


# Unpack UDP segment
def udp_segment(data):
    src_port, dest_port, length = struct.unpack('! H H H', data[:6])
    return src_port, dest_port, length, data[8:]

if __name__ == "__main__":
    main()
