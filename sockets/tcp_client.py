import socket
import sys

s = socket.socket()
host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
s.connect((host, 5000))

s.sendall(b"Hello Server!")
print(s.recv(1024).decode())

s.close()
