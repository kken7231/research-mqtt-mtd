import socket
import threading
import util
import sys

def create_socket():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(util.RECEPTION_ADDRESS)
        sock.listen(5)
        print(f"Listening on {util.RECEPTION_ADDRESS[0]}:{util.RECEPTION_ADDRESS[1]}")
        return sock
    except socket.error as e:
        print(f"Socket error: {e}")
        sys.exit(1)


def cleanup_connection(connection, lockinfo):
    try:
        connection.shutdown(socket.SHUT_RDWR)
    except socket.error as e:
        print(f"Socket shutdown error: {e}")
    try:
        connection.close()
    except socket.error as e:
        print(f"Socket close error: {e}")
    try:
        util.release_lock(lockinfo[0], lockinfo[1])
    except Exception as e:
        print(f"Error releasing lock: {e}")

def pop_random_topic_name(topic_name):
    try:
        with open(f'/mosquitto/{topic_name}', "rb") as f:
            topic_names = f.read()
    except IOError as e:
        print(f"File read error: {e}")
        return None, 0

    remaining = len(topic_names) // util.L_RAND_TOPIC_NAME - 1
    if remaining == 0:
        return None, 0

    try:
        with open(f'/mosquitto/{topic_name}', "wb") as f:
            f.write(topic_names[util.L_RAND_TOPIC_NAME:])
    except IOError as e:
        print(f"File write error: {e}")
        return None, 0

    return topic_names[:util.L_RAND_TOPIC_NAME], remaining

def handle_client_connection(connection):
    lockinfo = None
    try:
        data = connection.recv(1024)
        if data:
            print(f"Received: {util.toHex(data)}")
            given_topic_name = data[:util.L_RAND_TOPIC_NAME]
            topic_name = util.lookup_table(given_topic_name)
            if topic_name:
                lockinfo = util.acquire_lock(topic_name)
                if lockinfo:
                    tbllock = util.acquire_resolvTbl_lock()
                    if tbllock:
                        first_rand_topic_name, remaining = pop_random_topic_name(lockinfo[1])
                        if remaining == 0:
                            util.remove_table(lockinfo[1])
                        else:
                            util.update_table(lockinfo[1], first_rand_topic_name)
                        util.release_resolvTbl_lock(tbllock)
            else:
                topic_name = 'null'
            print(f"Topic Name: {topic_name}")
            connection.sendall(topic_name.encode())
    except (socket.error, IOError, Exception) as e:
        print(f"Error: {e}")
    finally:
        cleanup_connection(connection, lockinfo)

def main():
    sock = create_socket()

    while True:
        try:
            client_socket, client_address = sock.accept()
            print(f"Connection from {client_address}")
            threading.Thread(target=handle_client_connection, args=(client_socket,)).start()
        except socket.error as e:
            print(f"Socket accept error: {e}")
        except Exception as e:
            print(f"Unexpected error: {e}")

if __name__ == "__main__":
    main()