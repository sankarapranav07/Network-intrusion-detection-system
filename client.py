import socket
import time

SERVER_IP = '10.0.0.1'
SERVER_PORT = 8080
INTERVAL = 2  # Send a request every 2 seconds

print(f"[*] Starting normal user traffic generation -> {SERVER_IP}:{SERVER_PORT}")

while True:
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(3.0)
        client_socket.connect((SERVER_IP, SERVER_PORT))
        
        data = client_socket.recv(1024)
        print(f"[+] Server Response: {data.decode().strip()}")
        client_socket.close()
    except socket.timeout:
        print("[-] Connection timed out!")
    except Exception as e:
        print(f"[-] Connection failed (Traffic blocked or server down)")
    
    time.sleep(INTERVAL)
