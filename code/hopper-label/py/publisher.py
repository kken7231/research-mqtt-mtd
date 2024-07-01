from ssl import create_default_context, Purpose
from socket import create_connection
from os import makedirs, remove
from argparse import ArgumentParser
from string import ascii_letters, digits
from datetime import datetime
from base64 import b64encode
from common import (
    CLIENT_CERT_FILE, CLIENT_KEY_FILE,CA_FILE,  NUM_RANDOMIZED_TOPIC_NAMES,
    RANDOMIZED_TOPIC_NAME_LENGTH, FETCH_LABEL, PUBLISHER_OUTPUT_DIRECTORY,
    PACKET_TYPES, is_ascii_printable, print_packet
)

# Ensure output directory exists
makedirs(PUBLISHER_OUTPUT_DIRECTORY, exist_ok=True)

# Dictionary to manage topic_name - current randomized topic-name relationship
TOPIC_RANDOM_BYTES = {}

PACKET_TYPES = ['RESRVD', 'CONNECT', 'CONNACK', 'PUBLSH', 'PUBACK', 'PUBREC', 'PUBREL', 'PUBCMP', 'SUBSCR', 'SUBACK', 'UNSUBS', 'UNSUBA', 'PNGREQ', 'PNGRSP', 'DISCNT', 'AUTH  ']

def is_valid_hostname(hostname):
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1]
    allowed = set(ascii_letters + digits + "-")
    return all(char in allowed for char in hostname) and all(len(label) < 64 for label in hostname.split("."))

def is_valid_port(port):
    return 0 <= port <= 65535

def is_valid_topic_name(topic_name):
    return is_ascii_printable(topic_name.encode('ascii'))

def b64encode_mqttsafe(bs: bytes):
    return b64encode(bs, altchars=b'!@')

def print_packet(inout_spec: str, opponent: str, content: bytes):
    if inout_spec != 'from' and inout_spec != 'to':
        print('invalid inout_spec')
    packet_type = 'UDEFND'
    message = ''
    if len(content) > 1:
        packet_type = PACKET_TYPES[(content[0] & 0xF0) >> 4]
    if len(content) > 4 and content[3] > 0 and packet_type == 'PUBLSH':
        len_topic_name = content[3]
        if len(content) < 4 + len_topic_name:
            print('Error decoding topic name')
        else:
            message = f"topic name: \"{content[4:4+len_topic_name] if is_ascii_printable(content[4:4+len_topic_name]) else ' '.join(['%02X' % b for b in content])}\""
    print(f"{datetime.now().ctime()}| {opponent}{'=>' if inout_spec == 'from' else '<='} [{packet_type}] {' '.join(["%02X" % b for b in content]) if len(content) > 0 else ' (zero byte)'} ({message})")

# Function to connect to the TLS server
def connect_tls(host, port, topic_name):
    current_topic_name = None
    try:
        context = create_default_context(Purpose.SERVER_AUTH, cafile=CA_FILE)
        context.load_cert_chain(certfile=CLIENT_CERT_FILE, keyfile=CLIENT_KEY_FILE)
        with create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                data = f"{FETCH_LABEL}{topic_name}".encode()
                ssock.sendall(data)
                print_packet('to', host, data)
                response = ssock.recv(NUM_RANDOMIZED_TOPIC_NAMES*RANDOMIZED_TOPIC_NAME_LENGTH)
                print_packet('from', host, response)
                store_randomized_topic_names(topic_name, response[RANDOMIZED_TOPIC_NAME_LENGTH:])
                current_topic_name=response[:RANDOMIZED_TOPIC_NAME_LENGTH]
    except Exception as e:
        print(f"Error connecting to TLS server: {e}")
    finally:
        return current_topic_name
    
# Function to store random bytes in a file
def store_randomized_topic_names(topic_name: str, randomized_topic_names: bytes):
    if len(randomized_topic_names) < RANDOMIZED_TOPIC_NAME_LENGTH:
        raise Exception("No data as randomized topic names")
    file_path = PUBLISHER_OUTPUT_DIRECTORY / f"{host}-{port}-{topic_name}"
    with open(file_path, 'wb') as file:
        file.write(randomized_topic_names)

def pop_randomized_topic_name(host: str, port: int, topic_name: str):
    file_path = PUBLISHER_OUTPUT_DIRECTORY / f"{host}-{port}-{topic_name}"
    with open(file_path, 'rb') as file:
        randomized_topic_names = file.read()
    if len(randomized_topic_names) % RANDOMIZED_TOPIC_NAME_LENGTH != 0 or len(randomized_topic_names) == 0:
        print(len(randomized_topic_names),RANDOMIZED_TOPIC_NAME_LENGTH)
        raise Exception(f'Invalid File: {file_path}')
    if len(randomized_topic_names) < RANDOMIZED_TOPIC_NAME_LENGTH*2:
        remove(file_path)
    else:
        with open(file_path, 'wb') as file:
            file.write(randomized_topic_names[RANDOMIZED_TOPIC_NAME_LENGTH:])
    return randomized_topic_names[:RANDOMIZED_TOPIC_NAME_LENGTH]

def get_randomized_topic_name_from_normal(host: str, port: int, topic_name: str):
    file_path = PUBLISHER_OUTPUT_DIRECTORY / f"{host}-{port}-{topic_name}"
    try:
        if file_path.exists():
            return pop_randomized_topic_name(host, port, topic_name)
        else:
            return connect_tls(host, port, topic_name)
    except Exception as e:
        print(f"Error getting a randomized topic_name: {e}")
        return None

if __name__ == "__main__":
    parser = ArgumentParser(description="MQTT Topic Fetcher")
    parser.add_argument("host", help="Hostname of the MQTT server")
    parser.add_argument("port", type=int, help="Port number of the MQTT server")
    parser.add_argument("topic", help="MQTT topic name")

    args = parser.parse_args()

    host = args.host
    port = args.port
    topic_name = args.topic

    # Validate inputs
    if not is_valid_hostname(host):
        print("Invalid hostname")
    elif not is_valid_port(port):
        print("Invalid port number")
    elif not is_valid_topic_name(topic_name):
        print("Invalid topic name. It must be an ASCII string with printable characters.")
    else:
        # Proceed with connection and topic name fetching
        retrieved = get_randomized_topic_name_from_normal(host, port, topic_name)
        if retrieved:
            print(f"randomized: {b64encode_mqttsafe(retrieved).decode()}")
        else:
            print("Error found")