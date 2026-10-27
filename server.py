import socket
import sys

HOST = '0.0.0.0'  # Listen on all virtual interfaces
PORT = 8080

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Reuse port to avoid 'Address already in use' errors during rapid testing
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((HOST, PORT))
        server_socket.listen(10)
        print(f"[*] TCP Server active on {HOST}:{PORT}")
    except Exception as e:
        print(f"[-] Failed to bind socket: {e}")
        sys.exit(1)

    while True:
        try:
            conn, addr = server_socket.accept()
            print(f"[+] Legitimate Connection established from {addr[0]}:{addr[1]}")
            conn.sendall(b"ACK: Connection Received\n")
            conn.close()
        except KeyboardInterrupt:
            print("\n[*] Stopping Server...")
            server_socket.close()
            break

if __name__ == "__main__":
    start_server()
