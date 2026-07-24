import socket
import struct

sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)

print("Listening for UDP packets on port 12345.......")

while True:
    packet, addr = sock.recvfrom(65535)
    ip_header = packet[:20]
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
    version_ihl = iph[0]
    ihl = version_ihl & 0xF
    iph_length = ihl * 4 
    protocol = iph[6]

    if protocol != socket.IPPROTO_UDP:
        continue

    udp_header = packet[iph_length:iph_length+8]
    udph = struct.unpack('!HHHH', udp_header)
    src_port = udph[0]
    dest_port = udph[1]
    udp_length = udph[2]

    if dest_port != 12345:
        continue

    data_start = iph_length + 8
    data = packet[data_start:data_start + udp_length - 8]
    print(f"Received: {data.decode('utf-8', 'ignore')}")
