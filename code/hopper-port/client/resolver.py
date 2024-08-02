import socket
import ssl
import json
import struct
import sys
import os
import argparse

PORTS_LOCATION = '/mosquitto/ports/'

# Default values for hostname and port
hostname: str = 'localhost'
port: int = 8883
topic_name: str = ''

def fetch():
    print("fetch: %s %d" % (hostname, port))
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_verify_locations(cafile="/mosquitto/config/certs/ca/ca.crt")
    context.load_cert_chain(certfile="/mosquitto/config/certs/client/client.crt", keyfile="/mosquitto/config/certs/client/client.key")

    sock = socket.create_connection((hostname, port))
    secure_sock = context.wrap_socket(sock, server_hostname=hostname)
    secure_sock.sendall(topic_name.encode('utf-8'))
    response = secure_sock.recv(4096)
    try:
        secure_sock.shutdown(socket.SHUT_RDWR)
        secure_sock.close()
    except:
        pass

    ports = [struct.unpack('!h', response[i:i+2])[0] for i in range(0, len(response), 2)]

    if not os.path.exists(PORTS_LOCATION):
        os.mkdir(PORTS_LOCATION)
    with open(ports_file, 'w') as f:
        json.dump(ports, f)

def next_port():
    if not os.path.exists(ports_file):
        print("No ports available. Run 'fetch' first.")
        return

    with open(ports_file, 'r') as f:
        data = json.load(f)

    if not data:
        print("No ports available. Run 'fetch' first.")
        return

    port = data.pop(0)
    print(port)

    if not os.path.exists(PORTS_LOCATION):
        os.mkdir(PORTS_LOCATION)
    with open(ports_file, 'w') as f:
        json.dump(data, f)

def clear():
    if os.path.exists(ports_file):
        os.remove(ports_file)
        print("Ports cleared.")
    else:
        print("No ports to clear.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Manage ports with TLS.")
    parser.add_argument('-n', '--hostname', type=str, default='localhost', help='Server hostname (default: localhost)')
    parser.add_argument('-p', '--port', type=int, default=8883, help='Server port (default: 8883)')
    parser.add_argument('-t', '--topic_name', type=str, required=True, help='Topic name')

    subparsers = parser.add_subparsers(dest='command', required=True)

    subparsers.add_parser('fetch', help='Fetch ports from server.')
    subparsers.add_parser('next', help='Get the next available port.')
    subparsers.add_parser('clear', help='Clear the ports file.')

    args = parser.parse_args()

    # Update global variables based on command-line arguments
    hostname = args.hostname
    port = args.port
    topic_name = args.topic_name
    ports_file = PORTS_LOCATION + topic_name + '.json'

    if args.command == 'fetch':
        fetch()
    elif args.command == 'next':
        next_port()
    elif args.command == 'clear':
        clear()
    else:
        parser.print_help()