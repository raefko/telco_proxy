import socket
import threading
import signal
import sys
import select
import re

# Define the proxy server's IP and port
PROXY_IP = "127.0.0.1"
PROXY_PORT = 5060
PROXY_UDP_PORT = 5062
TARGET_IP = "80.156.100.67"
TARGET_PORT = 5060
PROXY_AUDIO = "m=audio 5062"
CLIENT_IP = "51.1.65.101"

tcp_socket = None
udp_socket = None


def udplog(data):
    print(f"[+][UDP] -- {data}")


def tcplog(data):
    print(f"[+][TCP] -- {data}")


def pretty_print_sip(data):
    try:
        message = data.decode("utf-8")
        lines = message.split("\r\n")
        print("----- SIP Packet -----")
        for line in lines:
            print(line)
        print("----------------------")
    except UnicodeDecodeError:
        print("Failed to decode SIP packet")


def is_rtp_packet(data):
    # RTP packets typically have a version number of 2 in the first two bits
    return len(data) > 1 and (data[0] >> 6) == 2


def handle_tcp_client(client_socket):
    global udp_socket
    # Connect to the target server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect((TARGET_IP, TARGET_PORT))

    def forward_data(source, destination):
        global udp_socket
        while True:
            data = source.recv(4096)
            if len(data) == 0:
                break
            if b"SIP" in data:
                # pretty_print_sip(data)
                # tcplog(f"Intercepted SIP packet: {data}")
                if PROXY_IP.encode() in data:
                    tcplog("===>")
                    tcplog(f"Replacing proxy IP with client IP")
                    data = data.replace(PROXY_IP.encode(), CLIENT_IP.encode())
                    if b"m=audio" in data:
                        pattern = re.compile(rb"m=audio \d+")
                        tcplog(
                            f"Replacing audio port {pattern} with proxy port {PROXY_AUDIO}"
                        )
                        data = re.sub(pattern, PROXY_AUDIO.encode(), data)
                        udp_socket = socket.socket(
                            socket.AF_INET, socket.SOCK_DGRAM
                        )
                        udp_socket.bind((PROXY_IP, PROXY_UDP_PORT))
                        udplog(
                            f"Proxy listening on {PROXY_IP}:{PROXY_UDP_PORT}"
                        )
                else:
                    tcplog("<===")
                    tcplog(f"Replacing target IP with proxy IP")
                    data = data.replace(TARGET_IP.encode(), PROXY_IP.encode())
            elif is_rtp_packet(data):
                print(f"Intercepted RTP packet: {data}")
            else:
                tcplog(f"Intercepted TCP packet: {data}")
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
                udplog(f"Intercepted SIP packet: {data}")
                if PROXY_IP.encode() in data:
                    udplog(f"Replacing proxy IP with client IP")
                    data = data.replace(PROXY_IP.encode(), CLIENT_IP.encode())
                else:
                    udplog(f"Replacing target IP with proxy IP")
                    data = data.replace(TARGET_IP.encode(), PROXY_IP.encode())
            elif is_rtp_packet(data):
                udplog(f"Intercepted RTP packet: {data}")
            else:
                udplog(f"Intercepted UDP packet: {data}")
                if PROXY_IP.encode() in data:
                    udplog(f"Replacing proxy IP with client IP")
                    data = data.replace(PROXY_IP.encode(), CLIENT_IP.encode())
                else:
                    udplog(f"Replacing target IP with proxy IP")
                    data = data.replace(TARGET_IP.encode(), PROXY_IP.encode())
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
    tcplog(f"Proxy listening on {PROXY_IP}:{PROXY_PORT}")

    # UDP socket
    # udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # udp_socket.bind((PROXY_IP, PROXY_PORT))
    # udplog(f"Proxy listening on {PROXY_IP}:{PROXY_PORT}")

    while True:
        # Use select to wait for incoming connections on both TCP and UDP sockets
        readable, _, _ = select.select([tcp_socket], [], [])

        for s in readable:
            if s == tcp_socket:
                # Handle TCP connections
                client_socket, addr = tcp_socket.accept()
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
    if tcp_socket:
        tcp_socket.close()
    if udp_socket:
        udp_socket.close()
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    start_proxy()
