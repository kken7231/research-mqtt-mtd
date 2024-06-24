import socket
import threading

LISTEN_PORT = 18830  # Change to your desired listen port
BROKER_PORT = 18834     # Change to your desired target port
BROKER_HOST = 'localhost'  # Change to the desired target host

def handle_client(client_socket, broker_address):
    """Handles a client connection and forwards data to BROKER_PORT."""
    try:
        # Connect to the target address
        broker_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        broker_socket.connect(broker_address)

        while True:
            # Receive data from the client
            data = client_socket.recv(1024)
            if not data:
                break

            # Send the data to the target address
            broker_socket.sendall(data)

            # Receive the response from the target address
            response = broker_socket.recv(1024)
            if not response:
                break

            # Send the response back to the client
            client_socket.sendall(response)
    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()
        broker_socket.close()

def start_server():
    """Starts the server that listens for incoming connections."""
    listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_socket.bind(('0.0.0.0', LISTEN_PORT))
    listen_socket.listen(5)

    print(f"Listening on port {LISTEN_PORT}")

    while True:
        try:
            client_socket, addr = listen_socket.accept()
            print(f"Accepted connection from {addr}")

            # Handle the client connection in a new thread
            client_handler = threading.Thread(
                target=handle_client,
                args=(client_socket, (BROKER_HOST, BROKER_PORT))
            )
            client_handler.daemon = True  # Ensure thread exits when main program exits
            client_handler.start()
        except KeyboardInterrupt:
            print("Server is shutting down.")
            break
        except Exception as e:
            print(f"Error accepting connections: {e}")

    listen_socket.close()

if __name__ == "__main__":
    start_server()