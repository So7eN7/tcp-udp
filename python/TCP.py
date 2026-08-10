import socket
import struct
import random

def checksum(data):
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + (data[i+1] if i+1 < len(data) else 0)
        s += w 
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff 

def send_tcp_packet(sock, dest_ip, src_ip, src_port, dest_port, seq, ack_seq, flags, data=b''):
    tcp_len = 20 + len(data)
    tcp_header = struct.pack('!HHLLBBHHH', src_port, dest_port, seq, ack_seq,
                             5 << 4, flags, 5840, 0, 0)
    pseudo_header = struct.pack('!4s4sBBH', socket.inet_aton(src_ip), socket.inet_aton(dest_ip), 
                                0, socket.IPPROTO_TCP, tcp_len)
    tcp_chksum = checksum(pseudo_header + tcp_header + data)
    tcp_header = struct.pack('!HHLLBBHHH', src_port, dest_port, seq, ack_seq, 5 << 4, flags, 5840, tcp_chksum, 0)

    total_len = 20 + tcp_len
    ip_header = struct.pack('!BBHHHBBH4s4s', 69, 0, total_len, 54321, 0, 64, socket.IPPROTO_TCP, 0, socket.inet_aton(src_ip), socket.inet_aton(dest_ip))
    ip_chksum = checksum(ip_header)
    ip_header = struct.pack('!BBHHHBBH4s4s', 69, 0, total_len, 54321, 0, 64, socket.IPPROTO_TCP, ip_chksum, socket.inet_aton(src_ip), socket.inet_aton(dest_ip))

    packet = ip_header + tcp_header + data
    sock.sendto(packet, (dest_ip, 0))

try:
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    
    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

    dest_ip = '127.0.0.1'
    src_ip = '127.0.0.1'
    src_port = 12345
    dest_port = 7

    my_seq = random.randint(0, 4295967295)
    my_ack = 0

    send_tcp_packet(send_sock, dest_ip, src_ip, src_port, dest_port, my_seq, my_ack, 2)
    print("SYN sent")

    while True:
        packet = recv_sock.recv(65535)
        ip_header = packet[:20]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        ihl = iph[0] & 0xF 
        iph_len = ihl * 4 
        if iph[6] != socket.IPPROTO_TCP or socket.inet_ntoa(iph[8]) != dest_ip or socket.inet_ntoa(iph[9]) != src_ip:
            continue

        tcp_header = packet[iph_len:iph_len+20]
        tcph = struct.unpack('!HHLLBBHHH', tcp_header)
        rx_src_port, rx_dest_port, rx_seq, rx_ack_seq, doff_reserved, rx_flags = tcph[:6]
        if rx_src_port != dest_port or rx_dest_port != src_port:
            continue
        if (rx_flags & 0x12) == 0x12 and rx_ack_seq == my_seq + 1:
            my_ack = rx_seq + 1 
            my_seq += 1 
            print("SYN-ACK received")
            break

    send_tcp_packet(send_sock, dest_ip, src_ip, src_port, dest_port, my_seq, my_ack, 16)
    print("ACK sent. Handshake complete")

except Exception as e:
    print(f"Error: {e}")
finally:
    send_sock.close()
    recv_sock.close()
