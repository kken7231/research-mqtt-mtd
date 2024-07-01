import socket
import ssl
import struct

# Define the server address and port
server_address = ('broker', 8883)

# Create a socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to the address and port
sock.bind(server_address)

# Listen for incoming connections
sock.listen(5)
print(f"Listening on {server_address[0]}:{server_address[1]}")

# Load the server's certificate and private key
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_verify_locations(cafile="/mosquitto/config/certs/ca/ca.crt")
context.load_cert_chain(certfile="/mosquitto/config/certs/broker/broker.crt", keyfile="/mosquitto/config/certs/broker/broker.key")

def shorts_to_bytes(shorts):
    fmt = '!' + 'h' * len(shorts)
    return struct.pack(fmt, *shorts)

def handle_client_connection(connection):
    try:
        data = connection.recv(1024)
        if data:
            print(f"Received: {data.decode()}")
            connection.sendall(shorts_to_bytes([1234, 2345, 3456, 4567, 5678]))
    finally:
        # Clean up the connection
        connection.shutdown(1)
        connection.close()

while True:
    # Wait for a connection
    client_socket, client_address = sock.accept()
    print(f"Connection from {client_address}")

    # Wrap the client socket with the SSL context
    secure_sock = context.wrap_socket(client_socket, server_side=True)
    try:
        handle_client_connection(secure_sock)
    except Exception as e:
        print(f"Exception: {e}")
        secure_sock.shutdown(1)
        secure_sock.close()