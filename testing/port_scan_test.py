import socket
import time
import sys

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
ports = [4998, 4999, 5000, 5001, 5002]

for port in ports:
     s = socket.socket()
     s.settimeout(0.5)

     result = s.connect_ex((host,port))

     if result == 0:
         print(port,"OPEN")
     else:
         print(port, "CLOSED")

     s.close()
     time.sleep(0.2)
