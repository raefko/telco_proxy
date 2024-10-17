import socket
import threading

# Define the proxy server's IP and port
PROXY_IP = "0.0.0.0"
PROXY_PORT = 5060
TARGET_IP = "80.156.100.67"
TARGET_PORT = 5060

CLIENT_IP = "51.1.65.101"


def handle_client(client_socket):
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
                data.replace(PROXY_IP.encode(), CLIENT_IP.encode())
                print("=====================================")
                print(f"Modified SIP packet: {data}")
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


def start_proxy():
    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_socket.bind((PROXY_IP, PROXY_PORT))
    proxy_socket.listen(5)
    print(f"Proxy listening on {PROXY_IP}:{PROXY_PORT}")

    while True:
        client_socket, addr = proxy_socket.accept()
        client_ip = addr[0]
        if client_ip == CLIENT_IP:
            print(f"Accepted connection from {addr}")
            client_handler = threading.Thread(
                target=handle_client, args=(client_socket,)
            )
            client_handler.start()
        else:
            print(f"Rejected connection from {addr}")
            client_socket.close()


if __name__ == "__main__":
    start_proxy()
