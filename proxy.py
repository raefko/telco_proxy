import socket
import threading
import signal
import sys
import select
import re

# Define the proxy server's IP and port
PROXY_IP = "0.0.0.0"
LOCAL_IP = "127.0.0.1"

PROXY_AUDIO = "m=audio 5062"
PROXY_PORT = 5060
PROXY_UDP_PORT = 5062

TARGET_IP = "80.156.100.67"
TARGET_PORT = 5060

CLIENT_IP = "51.1.65.101"

tcp_socket = None
udp_socket = None

socket_list = []
rtp_mapping = {}


def udplog(data):
    print(f"[+][UDP] -- {data}")


def tcplog(data):
    print(f"[+][TCP] -- {data}")


def pretty_print_sip(data, protocol):
    try:
        message = data.decode("utf-8")
        lines = message.split("\r\n")
        print(f"----- {protocol} == SIP Packet -----")
        for line in lines:
            print(line)
        print("----------------------")
    except UnicodeDecodeError:
        print("Failed to decode SIP packet")


def is_rtp_packet(data):
    # RTP packets typically have a version number of 2 in the first two bits
    return len(data) > 1 and (data[0] >> 6) == 2


def detect_method(data):
    methods = [
        "REGISTER",
        "INVITE",
        "ACK",
        "BYE",
        "OPTIONS",
        "CANCEL",
        "INFO",
        "PRACK",
        "SUBSCRIBE",
        "NOTIFY",
        "REFER",
        "MESSAGE",
        "PUBLISH",
        "UPDATE",
    ]
    for method in methods:
        if method.encode() in data:
            return method
    return None


def send_message(socket, data):
    print("[/] Sending...")
    socket.send(data)
    print("[/] Sent")


def handle_tcp_client(client_socket):
    global udp_socket, socket_list
    # Connect to the target server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect((TARGET_IP, TARGET_PORT))

    def forward_data(source, destination):
        global udp_socket
        while True:
            data = source.recv(4096)
            if len(data) == 0:
                break
            method = detect_method(data)
            if b"SIP" in data:
                if LOCAL_IP.encode() in data:
                    tcplog(f"|{method}| Sending ==>")
                    tcplog(f"Replacing {LOCAL_IP} with {CLIENT_IP}")
                    data = data.replace(LOCAL_IP.encode(), CLIENT_IP.encode())
                    pattern = re.compile(rb"m=audio (\d+)")
                    match = pattern.search(data)
                    if match:
                        original_port = match.group(1).decode()
                        udplog(
                            f"Replacing audio port {original_port} with proxy port {PROXY_UDP_PORT}"
                        )
                        data = re.sub(
                            pattern, str(PROXY_UDP_PORT).encode(), data
                        )
                else:
                    tcplog(f"|{method}| Receiving <===")
                    tcplog(f"Replacing {TARGET_IP} with {PROXY_IP}")
                    data = data.replace(TARGET_IP.encode(), PROXY_IP.encode())
            elif is_rtp_packet(data):
                print(f"Intercepted RTP packet: {data}")
            else:
                tcplog(f"Intercepted TCP packet: {data}")
            send_message(destination, data)

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


def handle_udp_client():
    global udp_socket, socket_list
    while True:
        data, addr = udp_socket.recvfrom(4096)
        client_ip = addr[0]
        if client_ip == CLIENT_IP:
            print(f"Accepted UDP connection from {addr}")
            # Create a UDP socket for the target server
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            def forward_data(source, destination, destination_address):
                while True:
                    data, addr = source.recvfrom(4096)
                    if len(data) == 0:
                        break
                    if b"SIP" in data:
                        pretty_print_sip(data, "udp")
                        # Replace the port number after "m=audio"
                        pattern = re.compile(rb"m=audio \d+")
                        data = re.sub(pattern, b"m=audio 5062", data)
                    elif is_rtp_packet(data):
                        print(f"Intercepted RTP packet: {data}")
                    else:
                        print(f"Intercepted UDP packet: {data}")
                    destination.sendto(data, destination_address)

            # Create threads to handle bidirectional data forwarding
            client_to_server = threading.Thread(
                target=forward_data,
                args=(udp_socket, server_socket, (TARGET_IP, TARGET_PORT)),
            )
            server_to_client = threading.Thread(
                target=forward_data, args=(server_socket, udp_socket, addr)
            )

            client_to_server.start()
            server_to_client.start()

            client_to_server.join()
            server_to_client.join()

            server_socket.close()
        else:
            print(f"Rejected UDP connection from {addr}")


def start_proxy():
    global tcp_socket, udp_socket, socket_list
    # TCP socket
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.bind((PROXY_IP, PROXY_PORT))
    tcp_socket.listen(5)
    socket_list.append(tcp_socket)
    tcplog(f"Proxy listening on {PROXY_IP}:{PROXY_PORT}")

    # UDP socket
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind((PROXY_IP, PROXY_UDP_PORT))
    socket_list.append(udp_socket)
    udplog(f"Proxy listening on {PROXY_IP}:{PROXY_UDP_PORT}")
    udp_thread = threading.Thread(target=handle_udp_client)
    udp_thread.start()
    while True:
        # Use select to wait for incoming connections on both TCP and UDP sockets
        readable, _, _ = select.select([tcp_socket], [], [])

        for s in readable:
            if s == tcp_socket:
                # Handle TCP connections
                client_socket, addr = tcp_socket.accept()
                socket_list.append(client_socket)
                client_ip = addr[0]
                tcplog(f"Connection from {addr}")
                client_handler = threading.Thread(
                    target=handle_tcp_client, args=(client_socket,)
                )
                client_handler.start()
            else:
                exit("Unknown socket")


def signal_handler(sig, frame):
    print("Shutting down proxy...")
    for s in socket_list:
        s.close()
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    start_proxy()
