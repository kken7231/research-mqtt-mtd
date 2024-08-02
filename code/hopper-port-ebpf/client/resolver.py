import socket
import ssl
import json
import struct
import sys
import os
import argparse
import util
import base64

TOPIC_NAMES_DIR = '/mosquitto/topic_names/'

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
    print(f"Fetched:  {util.toHex(response)}")
    try:
        secure_sock.shutdown(socket.SHUT_RDWR)
        secure_sock.close()
    except:
        pass

    if len(response)>util.L_RAND_TOPIC_NAME:
        if not os.path.exists(TOPIC_NAMES_DIR):
            os.mkdir(TOPIC_NAMES_DIR)
        with open(TOPIC_NAMES_DIR+topic_name, 'wb') as f:
            f.write(response)
        return 0
    return -1

def pop_name():
    if not os.path.exists(TOPIC_NAMES_DIR+topic_name):
        print("No names available. Running 'fetch'")
        ret = fetch()
        if ret != 0:
            print("Fetch failed")
            return

    with open(TOPIC_NAMES_DIR+topic_name, 'rb') as f:
        data = f.read()

    if not data:
        print("No names available")
        return

    rand_topic_name = data[:util.L_RAND_TOPIC_NAME]
    print(" ".join(["%02X" % b for b in rand_topic_name]))

    if len(data)<=util.L_RAND_TOPIC_NAME*2:
        os.remove(TOPIC_NAMES_DIR+topic_name)
    else:
        with open(TOPIC_NAMES_DIR+topic_name, 'wb') as f:
            f.write(data[util.L_RAND_TOPIC_NAME:])
        
def clear():
    if os.path.exists(TOPIC_NAMES_DIR+topic_name):
        os.remove(TOPIC_NAMES_DIR+topic_name)
        print("Names cleared.")
    else:
        print("No names to clear.")

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

    if args.command == 'fetch':
        fetch()
    elif args.command == 'next':
        pop_name()
    elif args.command == 'clear':
        clear()
    else:
        parser.print_help()