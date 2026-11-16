import socket
import time

target_ip = "10.0.0.1"
print(f"[*] Starting port scan on {target_ip}")

for port in range(8070, 8085):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        
        if s.connect_ex((target_ip, port)) == 0:
            print(f"Port {port} is open")
        else:
            print(f"Port {port} is closed")
        s.close()
    except Exception:
        pass
    time.sleep(0.1)

print("[*] Scan complete.")
