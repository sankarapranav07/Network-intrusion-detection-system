import socket
import time
import sys

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
for i in range(10):
    with socket.socket() as s:
         s.connect((host,5000))
         s.sendall(b"Normal traffic")
         print(s.recv(1024).decode())
    time.sleep(1)
