import socket
import ssl
import random
import struct
import datetime
import threading
import util
import sys

# Initialize the socket and SSL context
def create_socket():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(util.RESOLVER_ADDRESS)
        sock.listen(5)
        print(f"Listening on {util.RESOLVER_ADDRESS[0]}:{util.RESOLVER_ADDRESS[1]}")
        return sock
    except socket.error as e:
        print(f"Socket error: {e}")
        sys.exit(1)

def create_ssl_context():
    try:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_verify_locations(cafile=util.CA_FILE)
        context.load_cert_chain(certfile=util.CERT_FILE_BROKER, keyfile=util.KEY_FILE_BROKER)
        return context
    except ssl.SSLError as e:
        print(f"SSL error: {e}")
        sys.exit(1)


def cleanup_connection(connection, tbllock, lockinfo):
    try:
        connection.shutdown(socket.SHUT_RDWR)
    except socket.error as e:
        print(f"Socket shutdown error: {e}")
    try:
        connection.close()
    except socket.error as e:
        print(f"Socket close error: {e}")
    try:
        util.release_resolvTbl_lock(tbllock)
    except Exception as e:
        print(f"Error releasing table lock: {e}")
    try:
        util.release_lock(lockinfo[0], lockinfo[1])
    except Exception as e:
        print(f"Error releasing lock: {e}")

# Generate random topic names
def generate_random_topic_names(nbytes, nrands):
    assert nbytes > 0
    assert nrands > 0 and nrands <= 0x100
    return b''.join([struct.pack("!d", datetime.datetime.now(datetime.timezone.utc).timestamp())+bytes([i])+random.randbytes(nbytes) for i in range(nrands)])

# Save random topic names to a file
def save_random_topic_names(topic_name):
    try:
        topic_names = generate_random_topic_names(util.N_RANDBYTES, 100)
        assert len(topic_names) == util.L_RAND_TOPIC_NAME * 100
        with open(f'/mosquitto/{topic_name}', "wb") as f:
            f.write(topic_names)
        return topic_names
    except IOError as e:
        print(f"File error: {e}")
        return None

# Get the first random topic name from a file
def get_first_random_topic_name(topic_name):
    try:
        with open(f'/mosquitto/{topic_name}', "rb") as f:
            data = f.read()
        return data[:util.L_RAND_TOPIC_NAME]
    except IOError as e:
        print(f"File error: {e}")
        return None

# Remove the first random topic name from a file
def remove_first_random_topic_name(topic_name):
    try:
        with open(f'/mosquitto/{topic_name}', "rb") as f:
            data = f.read()
        if len(data) > util.L_RAND_TOPIC_NAME:
            with open(f'/mosquitto/{topic_name}', "wb") as f:
                f.write(data[util.L_RAND_TOPIC_NAME:])
    except IOError as e:
        print(f"File error: {e}")

# Handle client connections
def handle_client_connection(connection):
    lockinfo = None
    tbllock = None
    try:
        data = connection.recv(1024)
        if data:
            print(f"Received: {data.decode()}")
            generated_names = bytes([0x00])
            if util.MQTT_TOPIC_NAME_REGEX.match(data.decode()):
                topic_name = data.decode()
                lockinfo = util.acquire_lock(topic_name)
                if lockinfo:
                    tbllock = util.acquire_resolvTbl_lock()
                    if tbllock:
                        generated_names = save_random_topic_names(lockinfo[1])
                        if generated_names:
                            util.update_table(lockinfo[1], generated_names[:util.L_RAND_TOPIC_NAME])
                        else:
                            generated_names = bytes([0x00])
                        util.release_resolvTbl_lock(tbllock)
                        print(f"First topic name: {util.toHex(generated_names[:util.L_RAND_TOPIC_NAME])}")
            connection.sendall(generated_names)
    except socket.error as e:
        print(f"Socket error: {e}")
    except IOError as e:
        print(f"I/O error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
    finally:
        cleanup_connection(connection, tbllock, lockinfo)

def main():
    sock = create_socket()
    context = create_ssl_context()

    while True:
        try:
            client_socket, client_address = sock.accept()
            print(f"Connection from {client_address}")
            secure_sock = context.wrap_socket(client_socket, server_side=True)
            client_thread = threading.Thread(target=handle_client_connection, args=(secure_sock,))
            client_thread.start()
        except socket.error as e:
            print(f"Socket accept error: {e}")
        except Exception as e:
            print(f"Unexpected error: {e}")

if __name__ == "__main__":
    main()