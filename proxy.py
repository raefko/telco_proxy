import socket
import threading
import signal
import sys
import select

# Define the proxy server's IP and port
PROXY_IP = "0.0.0.0"
PROXY_PORT = 5060
TARGET_IP = "80.156.100.67"
TARGET_PORT = 5060

CLIENT_IP = "51.1.65.101"

tcp_socket = None
udp_socket = None


def handle_tcp_client(client_socket):
    # Connect to the target server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect((TARGET_IP, TARGET_PORT))

    def forward_data(source, destination):
        while True:
            data = source.recv(4096)
            if len(data) == 0:
                break
            if b"SIP" in data:
                print(f"Intercepted SIP packet: {data}")
            destination.send(data)

    # Create threads to handle bidirectional data forwarding
    client_to_server = threading.Thread(
        target=forward_data, args=(client_socket, server_socket)
    )
    server_to_client = threading.Thread(
        target=forward_data, args=(server_socket, client_socket)
    )

    client_to_server.start()
    server_to_client.start()

    client_to_server.join()
    server_to_client.join()

    client_socket.close()
    server_socket.close()


def handle_udp_client(client_socket, client_address):
    # Create a UDP socket for the target server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def forward_data(source, destination, destination_address):
        while True:
            data, addr = source.recvfrom(4096)
            if len(data) == 0:
                break
            if b"SIP" in data:
                print(f"Intercepted SIP packet: {data}")
            destination.sendto(data, destination_address)

    # Create threads to handle bidirectional data forwarding
    client_to_server = threading.Thread(
        target=forward_data,
        args=(client_socket, server_socket, (TARGET_IP, TARGET_PORT)),
    )
    server_to_client = threading.Thread(
        target=forward_data, args=(server_socket, client_socket, client_address)
    )

    client_to_server.start()
    server_to_client.start()

    client_to_server.join()
    server_to_client.join()

    client_socket.close()
    server_socket.close()


def start_proxy():
    global tcp_socket, udp_socket
    # TCP socket
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.bind((PROXY_IP, PROXY_PORT))
    tcp_socket.listen(5)
    print(f"TCP Proxy listening on {PROXY_IP}:{PROXY_PORT}")

    # UDP socket
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind((PROXY_IP, PROXY_PORT))
    print(f"UDP Proxy listening on {PROXY_IP}:{PROXY_PORT}")

    while True:
        # Use select to wait for incoming connections on both TCP and UDP sockets
        readable, _, _ = select.select([tcp_socket, udp_socket], [], [])

        for s in readable:
            if s == tcp_socket:
                # Handle TCP connections
                client_socket, addr = tcp_socket.accept()
                client_ip = addr[0]
                if client_ip == CLIENT_IP:
                    print(f"Accepted TCP connection from {addr}")
                    client_handler = threading.Thread(
                        target=handle_tcp_client, args=(client_socket,)
                    )
                    client_handler.start()
                else:
                    print(f"Rejected TCP connection from {addr}")
                    client_socket.close()
            elif s == udp_socket:
                # Handle UDP connections
                data, addr = udp_socket.recvfrom(4096)
                client_ip = addr[0]
                if client_ip == CLIENT_IP:
                    print(f"Accepted UDP connection from {addr}")
                    client_handler = threading.Thread(
                        target=handle_udp_client, args=(udp_socket, addr)
                    )
                    client_handler.start()
                else:
                    print(f"Rejected UDP connection from {addr}")


def signal_handler(sig, frame):
    print("Shutting down proxy...")
    if tcp_socket:
        tcp_socket.close()
    if udp_socket:
        udp_socket.close()
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    start_proxy()
