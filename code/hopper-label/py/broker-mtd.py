from os import makedirs, remove
from time import sleep, time_ns
from socket import AF_INET, SHUT_RDWR, SOCK_STREAM, create_connection, error, socket
from struct import pack
from secrets import token_bytes
from ssl import SSLSocket, create_default_context, Purpose
from threading import Lock, Thread
from typing import Dict, List
from common import (
    PORT_BROKER, NUM_RANDOMIZED_TOPIC_NAMES,
    RANDOMIZED_TOPIC_NAME_LENGTH, FETCH_LABEL, SERVER_ADDRESS_8883,
    SERVER_ADDRESS_1883, PACKET_TYPES, b64decode_mqttsafe, print_packet,
    CERT_FILE, CA_FILE, KEY_FILE, BROKER_OUTPUT_DIRECTORY
)

context = create_default_context(Purpose.CLIENT_AUTH)
context.load_verify_locations(cafile=CA_FILE)
context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

# Ensure output directory exists
makedirs(BROKER_OUTPUT_DIRECTORY, exist_ok=True)

TOPIC_RANDOM_BYTES: Dict[bytes, bytes] = {}
active_threads: List[Thread] = []

def get_raw_bytes(bs: bytes) -> bytes:
    return bs if len(bs) % 4 != 0 else b64decode_mqttsafe(bs)

def replace_randomized_topic_name_to_normal(packet_data: bytes, client_ip: str) -> bytes:
    global TOPIC_RANDOM_BYTES

    if len(packet_data) < 4 or PACKET_TYPES[(packet_data[0] & 0xF0) >> 4] != 'PUBLISH' or packet_data[3] == 0:
        raise Exception("Cannot read its topic name")

    len_randomized_topic_name = packet_data[3]
    if len(packet_data) < 4 + len_randomized_topic_name:
        raise Exception("Illegal packet, probably topic name length is wrong")

    randomized_topic_name = get_raw_bytes(packet_data[4:4 + len_randomized_topic_name])

    if len(randomized_topic_name) != RANDOMIZED_TOPIC_NAME_LENGTH:
        raise Exception(f"Illegal randomized topic name: {len(randomized_topic_name)}")

    if randomized_topic_name not in TOPIC_RANDOM_BYTES:
        raise Exception(f"No topic found: {TOPIC_RANDOM_BYTES}")

    if len(TOPIC_RANDOM_BYTES[randomized_topic_name]) > 0xFF:
        raise Exception("Found a too long topic name")

    to_topic_name = TOPIC_RANDOM_BYTES[randomized_topic_name]
    del TOPIC_RANDOM_BYTES[randomized_topic_name]

    file_path = BROKER_OUTPUT_DIRECTORY / f"{to_topic_name.decode()}-{client_ip}"
    if file_path.exists():
        with open(file_path, 'rb') as f:
            random_topic_names = f.read()

        TOPIC_RANDOM_BYTES[random_topic_names[:RANDOMIZED_TOPIC_NAME_LENGTH]] = to_topic_name
        if len(random_topic_names) < RANDOMIZED_TOPIC_NAME_LENGTH * 2 or len(random_topic_names) % RANDOMIZED_TOPIC_NAME_LENGTH != 0:
            remove(file_path)
        else:
            with open(file_path, 'wb') as f:
                f.write(random_topic_names[RANDOMIZED_TOPIC_NAME_LENGTH:])

    new_packet_len = ((packet_data[2] << 8) + packet_data[1]) - len_randomized_topic_name + len(to_topic_name)
    new_packet_data = (
        packet_data[0:1] +
        bytes([new_packet_len & 0xFF, (new_packet_len >> 8) & 0xFF, len(to_topic_name)]) +
        to_topic_name +
        packet_data[4 + len_randomized_topic_name:]
    )
    return new_packet_data

def replace_randomized_topic_name_to_normal_if_publish(packet_data: bytes, client_ip: str) -> bytes:
    if len(packet_data) > 4 and PACKET_TYPES[(packet_data[0] & 0xF0) >> 4] == 'PUBLISH' and packet_data[3] > 0:
        return replace_randomized_topic_name_to_normal(packet_data, client_ip)
    else:
        return packet_data

def generate_and_save_unique_randomized_topic_names(topic_name: bytes, client_ip: str, total_length: int = RANDOMIZED_TOPIC_NAME_LENGTH, number_of_randoms: int = NUM_RANDOMIZED_TOPIC_NAMES) -> bytes:
    global TOPIC_RANDOM_BYTES

    if total_length % 4 == 0:
        raise Exception("Randomized bytes must not be a multiple of 4 to be distinguished from base64 encoded string")
    if number_of_randoms < 0:
        raise Exception("Number of randoms must be positive")

    with Lock():
        timestamp = pack('!Q', time_ns())[0:7] # Ignores the least significant byte
        timestamp_len =len(timestamp)
        topic_key = f"{topic_name.decode()}-{client_ip}"
        file_path = BROKER_OUTPUT_DIRECTORY / topic_key
        random_bytes = bytes()
        for _ in range(number_of_randoms - 1):
            random_bytes += timestamp + token_bytes(total_length - timestamp_len)
        with open(file_path, 'wb') as f:
            f.write(random_bytes)
        first_topic_name = timestamp + token_bytes(total_length - timestamp_len)
        TOPIC_RANDOM_BYTES[first_topic_name] = topic_name
        return first_topic_name + random_bytes

def handle_tls_client_connection(conn: SSLSocket, addr: tuple[str, int]) -> None:
    print(f"TLS connection established from {addr}")
    addr_str = f"{addr[0]}:{addr[1]}"
    try:
        data = conn.recv(1024)
        print_packet('from', addr_str, 8883, data)
        datastr = data.decode()
        response = bytes()
        if datastr.startswith(FETCH_LABEL):
            topic_name = data[len(FETCH_LABEL):]
            if topic_name and b'+' not in topic_name and b'#' not in topic_name:
                response = generate_and_save_unique_randomized_topic_names(topic_name, addr[0])
            else:
                print(f"No valid topic name {topic_name}")
        else:
            print(f"No label {FETCH_LABEL}")
        conn.sendall(response)
        print_packet('to', addr_str, 8883, response)
    except Exception as e:
        print(f"Error with TLS connection {addr}: {e}")
    finally:
        conn.shutdown(SHUT_RDWR)
        conn.close()
        print(f"TLS connection closed from {addr}")

def handle_plain_client_connection(conn: socket, addr: tuple[str, int]) -> None:
    print(f"Plain connection established from {addr}")
    addr_str = f"{addr[0]}:{addr[1]}"
    with create_connection(('localhost', PORT_BROKER)) as broker_conn:
        while True:
            try:
                data = conn.recv(1024)
                if len(data) == 0:
                    break
                print_packet('from', addr_str, 1883, data)
                response = bytes()
                try:
                    data = replace_randomized_topic_name_to_normal_if_publish(data, addr[0])
                except Exception as e:
                    print(f"Unexpected error with replacing the topic name from {addr}: {e}")

                try:
                    broker_conn.sendall(data)
                    print_packet('to', 'broker', 1883, data)
                    response = broker_conn.recv(1024)
                    print_packet('from', 'broker', 1883, response)
                except error as broker_error:
                    print(f"Error communicating with broker from {addr}: {broker_error}")
                    break

                conn.sendall(response)
                print_packet('to', addr_str, 1883, response)
            except error as client_error:
                print(f"Error receiving data from client {addr}: {client_error}")
                break
            except Exception as e:
                print(f"Unexpected error with plain connection {addr}: {e}")
                break
        try:
            conn.shutdown(SHUT_RDWR)
            conn.close()
            print(f"Plain connection closed from {addr}")
        except error as close_error:
            print(f"Error closing connection with {addr}: {close_error}")

def run_server(address: tuple[str, int], use_tls: bool = False) -> None:
    global active_threads
    sock = socket(AF_INET, SOCK_STREAM)
    sock.bind(address)
    sock.listen(5)
    print(f"Listening on {address} ({'TLS' if use_tls else 'Plain'})")
    while True:
        conn, addr = sock.accept()
        if use_tls:
            conn = context.wrap_socket(conn, server_side=True)
            thread = Thread(target=handle_tls_client_connection, args=(conn, addr))
        else:
            thread = Thread(target=handle_plain_client_connection, args=(conn, addr))
        thread.start()
        active_threads.append(thread)

# Start servers
tls_server_thread = Thread(target=run_server, args=(SERVER_ADDRESS_8883, True), daemon=True)
plain_server_thread = Thread(target=run_server, args=(SERVER_ADDRESS_1883, False), daemon=True)
tls_server_thread.start()
plain_server_thread.start()

print("TLS server and plain server are running in background threads.")

def monitor_threads() -> None:
    global active_threads
    while True:
        active_threads = [t for t in active_threads if t.is_alive()]
        sleep(3)  # Adjust the sleep time as necessary

monitor_thread = Thread(target=monitor_threads, daemon=True)
monitor_thread.start()

# Main thread can continue with other tasks or keep running
try:
    while True:
        sleep(1)
except KeyboardInterrupt:
    for file in BROKER_OUTPUT_DIRECTORY.glob("*"):
        remove(file)
        print(f"Removed file {file}")
    print("Shutting down servers...")
