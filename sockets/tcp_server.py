import socket
import threading

def handle_client(conn,addr):
    print("Connected:",addr)
    with conn:
         while True:
               data = conn.recv(1024)
               if not data:
                   break
               conn.sendall(b"ACK: " + data)

def main():
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0",5000))
    server.listen(10)
   
    print("TCP Server running on port 5000")

    while True:
        conn, addr = server.accept()
        threading.Thread(
           target=handle_client,
           args=(conn, addr),
           daemon=True
        ).start()

main()
