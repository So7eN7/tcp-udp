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

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    dest_ip = '127.0.0.1'
    src_ip = '127.0.0.1'
    src_port = 12345
    dest_port = 7
    seq = random.randint(0, 4295967295)
    ack_seq = 0
    doff = 5
    fin = 0; syn = 1; rst = 0; psh = 0; ack = 0; urg = 0;
    flags = fin + (syn << 1) + (rst << 2) + (psh << 3) + (ack << 4) + (urg << 5)
    window = socket.htons(5840)
    check = 0
    urg_ptr = 0

    tcp_header = struct.pack('!HHLLBBHHH', src_port, dest_port, seq, ack_seq,
                             doff << 4, flags, window, check, urg_ptr)
    pseudo_header = struct.pack('!4s4sBBH', socket.inet_aton(src_ip), socket.inet_aton(dest_ip), 
                                0, socket.IPPROTO_TCP, len(tcp_header))
    pseudo_packet = pseudo_header + tcp_header
    tcp_check = checksum(pseudo_packet)

    tcp_header = struct.pack('!HHLLBBHHH', src_port, dest_port, seq, ack_seq,
                             doff << 4, flags, window, tcp_check, urg_ptr)
    
    total_len = 20 + len(tcp_header)
    ip_header = struct.pack('!BBHHHBBH4s4s', 4 << 4 | 5, 0, total_len, 54321, 0, 64,
                            socket.IPPROTO_TCP, 0, socket.inet_aton(src_ip), socket.inet_aton(dest_ip))
    ip_check = checksum(ip_header)
    ip_header = struct.pack('!BBHHHBBH4s4s', 4 << 4 | 5, 0, total_len, 54321, 0, 64,
                            socket.IPPROTO_TCP, ip_check, socket.inet_aton(src_ip), socket.inet_aton(dest_ip))

    packet = ip_header + tcp_header
    sock.sendto(packet, (dest_ip, 0))
    print("TCP SYN sent")
except Exception as e:
    print(f"Error: {e}")
finally:
    sock.close()
