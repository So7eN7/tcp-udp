import socket
import struct
import sys

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
    ip_header = struct.pack('!BBHHHBBH4s4s', #network byte order
                            4 << 4 | 5, #version | ihl 
                            0, # tos
                            20 + 5, # total length (header + "hello")
                            54321, # id 
                            0, # frag_off
                            64, # ttl 
                            socket.IPPROTO_UDP, # protocol placeholder
                            0, # checksum placeholder
                            socket.inet_aton(src_ip),
                            socket.inet_aton(dest_ip))
    data = b'hello'
    packet = ip_header + data

    chksum = checksum(packet)
    ip_header = struct.pack('!BBHHHBBH4s4s',
                            4 << 4 | 5, 0, 20+5, 54321, 0, 64,
                            socket.IPPROTO_UDP, chksum, 
                            socket.inet_aton(src_ip), socket.inet_aton(dest_ip))
    packet = ip_header + data

    sock.sendto(packet, (dest_ip, 0))
    print("IP packet sent")
except socket.error as err:
    print(f"error: {err}")
    sys.exit(1)
finally:
    sock.close()
