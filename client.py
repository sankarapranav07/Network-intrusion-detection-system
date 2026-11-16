import socket
import time

SERVER_IP = '10.0.0.1'
SERVER_PORT = 8080
INTERVAL = 2  

print(f"[*] Starting normal traffic to {SERVER_IP}:{SERVER_PORT}")

while True:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect((SERVER_IP, SERVER_PORT))
        
        data = s.recv(1024)
        print(f"[+] Response: {data.decode().strip()}")
        s.close()
    except Exception:
        print("[-] Connection failed")
    
    time.sleep(INTERVAL)
