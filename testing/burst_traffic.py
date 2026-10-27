import socket 
import time
import sys

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
start = time.time()

for i in range(30):
    try:
       with socket.socket() as s:
           s.settimeout(1)
           s.connect((host,5000))
           s.sendall(b"Test traffic")
           s.recv(1024)
           print("Connection",i+1,"OK")
    except Exception as e:
         print("Failed:",e)

print("Time taken:",round(time.time() - start,2))

