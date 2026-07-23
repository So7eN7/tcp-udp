import socket
import sys

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    print("Raw socket set up")
except socket.error as err:
    print(f"Socket creation failed: {err}")
    sys.exit(1)
finally:
    sock.close()
