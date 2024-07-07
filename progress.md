# MQTT & MTD

## 2024/06/20

### Paper Reading

- "Securing MQTT Ecosystem: Exploring Vulenrabilities, Mitigations, and Future Trajectories"

### Slide Making

- Summarize the current status on what I recognize
  ![slide](img/20240620_suggest.png)

### Video call with Koide Sensei

- Add the title and the purpose to slides
  - Issues/senarios it can solve
- Proceed to the Introduction section in the paper
  - One reference per one paragraph
  - Contents
    - Purpose
    - What is Sensor Network
    - Current problems in the field of Sensor Network
    - What is MTD (quote a prominent MTD textbook(?))
    - How to solve the problems using MTD
    - (Brief) result
- Dynamic instansing of MQTT Broker
  - Following interactions can be not on SSL/TLS
- To do
  1. Title & Purpose
  2. Look up the conference to write on
  3. Introduction
  4. Prototyping

### Prototype Image

- Random (per `TIMEFRAME_RANDOM` per topic)
  - as auth, used for calculating the instance/port
  - Maybe increment of the sequence number?
- VM Instantiation/Port distribution (per `TIMEFRAME_INSTANTIATION` per topic)
  - Comparison between two?
- Worthless topic name in a packet (distinguishes by instance/port accessed)

### Prevents

- Malicious publish/subscribe access
- DoS attacks
- No change on packet content layout from clients

### Conference candidates

- 2024 IEEE International Workshop on Information Forensics and Security (WIFS)
  - **Location** Rome, Italy
  - **Call for Papers Deadline** 30 June 2024
  - **IEEE URL** https://conferences.ieee.org/conferences_events/conferences/conferencedetails/61860
  - **Conference URL** https://wifs2024.uniroma3.it/
- 2024 7th International Conference on Advanced Communication Technologies and Networking (CommNet)
  - **Location** Rabat, Morocco
  - **Call for Papers Deadline** 31 July 2024
  - **IEEE URL** https://conferences.ieee.org/conferences_events/conferences/conferencedetails/63022
  - **Conference URL** https://www.commnet-conf.org/
- 2024 International Conference on Smart Electronics and Communication Systems (ISENSE)
  - **Location** Kottayam, India
  - **Call for Papers Deadline** 18 August 2024
  - **IEEE URL** https://conferences.ieee.org/conferences_events/conferences/conferencedetails/63713
  - **Conference URL** https://isense24.iiitkottayam.ac.in/

## 2024/06/21

### Mosquitto Broker & Clients

```
commit 2435501b209482efccb5aa4e9c69c0a82b697827 (HEAD -> main)
Author: Kentaro Kusumi <spamkenxx@gmail.com>
Date:   Fri Jun 21 15:50:49 2024 +0900

    First prototype
```

```yaml
# code/docker-compose.yml
services:
  # Broker
  broker:
    # build:
    #   context: ~/git/mosquitto/docker/2.0-openssl
    #   args:
    #     - VERSION=2.0.18
    # image: eclipse-mosquitto:2.0.18
    # volumes:
    #   - ~/git/mosquitto/docker/2.0-openssl/mosquitto-no-auth.conf:/mosquitto/config/mosquitto.conf

    build:
      context: ./mosquitto-broker
    volumes:
      - ./mosquitto-broker/mosquitto.conf:/mosquitto/config/mosquitto.conf
    tty: true
    stdin_open: true
    ports:
      - "1883:1883"
    restart: always

  # Publisher
  pub:
    build:
      context: ./mosquitto-cli
    tty: true

  # Subscriber 1
  sub1:
    build:
      context: ./mosquitto-cli
    tty: true

  # Subscriber 2
  sub2:
    build:
      context: ./mosquitto-cli
    tty: true
```

```dockerfile
# code/mosquitto-broker/Dockerfile
FROM alpine:3.20.1

# Install mosquitto
RUN apk update && \
    apk add --no-cache mosquitto=2.0.18-r0

EXPOSE 1883

CMD mosquitto -c /mosquitto/config/mosquitto.conf
```

```conf
# code/mosquitto-broker/mosquitto.conf
# This is a Mosquitto configuration file that creates a listener on port 1883
# that allows unauthenticated access.

listener 1883
allow_anonymous true
```

```dockerfile
# code/mosquitto-cli/Dockerfile
FROM alpine:3.20.1

# Install mosquitto-clients
RUN apk update && \
    apk add --no-cache mosquitto-clients=2.0.18-r0
```

#### 1. Compose All

```sh
cd ~/Library/CloudStorage/OneDrive-KyushuUniversity/小出研2024/MQTT_MTD_eBPF_research/code
docker-compose up --build
```

#### 2. Publisher Client

```sh
docker-compose exec pub sh
mosquitto_pub -h broker -t 'sample-topics' -m 'Hello from publisher'
```

#### 3. Subscriber Client

```sh
docker-compose exec sub1 sh
mosquitto_sub -h broker -t 'sample-topics'
```

<!-- <video src="img/20240621_first_proto.mov" controls="true"></video> -->

## 2024/06/22

### Linux VM for MQTT Broker

#### Environment

UTM for macOS 4.4.4
Ubuntu server for arm64 22.04 LTS

#### Setup

##### Mosquitto

```sh
sudo apt install mosquitto # mosquitto 2.0.18
```

```conf
# ~/mosquitto/mosquitto.conf
# This is a Mosquitto configuration file that creates a listener on port 1883
# that allows unauthenticated access.

listener 18834
allow_anonymous true
```

##### BCC (https://github.com/iovisor/bcc)

https://github.com/iovisor/bcc/blob/master/INSTALL.md#ubuntu---source
(Additionaly included libpolly-14-dev)

```sh
mkdir ebpf
cd ebpf
git clone https://github.com/iovisor/bcc
sudo apt install -y zip bison build-essential cmake flex git libedit-dev \
  libllvm14 llvm-14-dev libclang-14-dev libpolly-14-dev python3 zlib1g-dev \
  libelf-dev libfl-dev python3-setuptools \
  liblzma-dev libdebuginfod-dev arping netperf iperf
mkdir bcc/build; cd bcc/build
cmake ..
make
sudo make install
cmake -DPYTHON_CMD=python3 .. # build python3 binding
pushd src/python/
make
sudo make install
popd
```

## 2024/06/23

### No eBPF, just packet handover between sockets

```python
# handoverer/handoverer.py
import socket
import threading

LISTEN_PORT = 18830
BROKER_PORT = 18834
BROKER_HOST = 'localhost'

def handle_client(client_socket, broker_address):
    """Handles a client connection and forwards data to BROKER_PORT."""
    try:
        broker_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        broker_socket.connect(broker_address)

        while True:
            data = client_socket.recv(1024)
            if not data:
                break

            broker_socket.sendall(data)

            response = broker_socket.recv(1024)
            if not response:
                break

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

            client_handler = threading.Thread(
                target=handle_client,
                args=(client_socket, (BROKER_HOST, BROKER_PORT))
            )
            client_handler.daemon = True
            client_handler.start()
        except KeyboardInterrupt:
            print("Server is shutting down.")
            break
        except Exception as e:
            print(f"Error accepting connections: {e}")
            break;

    listen_socket.close()

if __name__ == "__main__":
    start_server()
```

```conf
# handover/mosquitto.conf
# This is a Mosquitto configuration file that creates a listener on port 1883
# that allows unauthenticated access.

listener 18834 127.0.0.1 # only allowed from localhost
allow_anonymous true
socket_domain ipv4
```

<!-- <video src="img/20240623_packet_handover.mov" controls="true"></video> -->

![img](img/20240623_packet_handover_pic.png)

### Idea

- Answers as normal on every port possible using eBPF?
- VM Instance - too costy, go with just python packet handovering
- Hash as a topic name in a publish packet and no tls -> reduces crypto usage
- Port changing & calculation method - to be discussed

## 2024/06/24

### TLS-enabled Mosquitto connection

Ref: [https://openest.io/en/services/mqtts-how-to-use-mqtt-with-tls/](https://openest.io/en/services/mqtts-how-to-use-mqtt-with-tls/)

```sh
mkdir certs; cd certs
mkdir ca; cd ca
openssl req -new -x509 -days 365 -extensions v3_ca -keyout ca.key -out ca.crt # passphrase "mqttca"
```

```
..+.....+......+.+++++++++++++++++++++++++++++++++++++++*........+++++++++++++++++++++++++++++++++++++++*.+...+....+......+........+....+......+............+........+.+...+...+.........+.....+..................+.+......+.....+...+.+...............+..+............+...............+..........+...+........+.++++++
...+....+...+..............+..........+.....+++++++++++++++++++++++++++++++++++++++*..........+...........+...+.+...+++++++++++++++++++++++++++++++++++++++*...+..........+...+.....+..........+..+.......+..+................+..+...............+......+......++++++
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:
-----
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:JP
State or Province Name (full name) [Some-State]:Fukuoka
Locality Name (eg, city) []:Fukuoka
Organization Name (eg, company) [Internet Widgits Pty Ltd]:Kyudai
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:server
Email Address []:aaa@nonexistent
```

```sh
cd ..
mkdir broker; cd broker
openssl genrsa -out broker.key 2048
openssl req -out broker.csr -key broker.key -new
```

```
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:JP
State or Province Name (full name) [Some-State]:Fukuoka
Locality Name (eg, city) []:Fukuoka
Organization Name (eg, company) [Internet Widgits Pty Ltd]:Kyudai
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:broker
Email Address []:bbb@nonexistent

Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:
An optional company name []:
```

```sh
openssl x509 -req -in broker.csr -CA ../ca/ca.crt -CAkey ../ca/ca.key -CAcreateserial -out broker.crt -days 100
```

```
Certificate request self-signature ok
subject=C=JP, ST=Fukuoka, L=Fukuoka, O=Kyudai, CN=broker, emailAddress=bbb@nonexistent
Enter pass phrase for ../ca/ca.key:
```

```sh
cd ..
mkdir client; cd client
openssl genrsa -out client.key 2048
openssl req -out client.csr -key client.key -new
```

```
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:JP
State or Province Name (full name) [Some-State]:Fukuoka
Locality Name (eg, city) []:Fukuoka
Organization Name (eg, company) [Internet Widgits Pty Ltd]:Kyudai
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:localhost
Email Address []:ccc@nonexistent

Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:
An optional company name []:
```

```sh
openssl x509 -req -in client.csr -CA ../ca/ca.crt -CAkey ../ca/ca.key -CAcreateserial -out client.crt -days 100
```

```
Certificate request self-signature ok
subject=C=JP, ST=Fukuoka, L=Fukuoka, O=Kyudai, CN=localhost, emailAddress=ccc@nonexistent
Enter pass phrase for ../ca/ca.key:
```

![img](img/20240624_fs.png)

```conf
# tls-only/broker/mosquitto.conf
# This is a Mosquitto configuration file that creates a listener on port 1883
# that allows unauthenticated access.

listener 8883
allow_anonymous true
socket_domain ipv4
cafile /mosquitto/config/certs/ca/ca.crt
certfile /mosquitto/config/certs/broker/broker.crt
keyfile /mosquitto/config/certs/broker/broker.key
require_certificate true
```

```dockerfile
# tls-only/broker/Dockerfile
FROM alpine:3.20.1

# Install mosquitto
RUN apk update && \
    apk add --no-cache mosquitto=2.0.18-r0

EXPOSE 8883

CMD mosquitto -c /mosquitto/config/mosquitto.conf
```

```yaml
# tls-only/docker-compose.yml
services:
  # Broker
  broker:
    build:
      context: ./broker
    volumes:
      - ./broker/mosquitto.conf:/mosquitto/config/mosquitto.conf
      - ../certs/broker:/mosquitto/config/certs/broker
      - ../certs/ca:/mosquitto/config/certs/ca
    hostname: broker
    tty: true
    stdin_open: true
    ports:
      - "8883:8883"
    restart: always
    networks:
      - net

  # Publisher
  pub:
    build:
      context: ../../mosquitto-cli
    volumes:
      - ../certs/client:/mosquitto/config/certs/client
      - ../certs/ca:/mosquitto/config/certs/ca
    hostname: publisher
    tty: true
    networks:
      - net

  # Subscriber
  sub:
    build:
      context: ../../mosquitto-cli
    volumes:
      - ../certs/client:/mosquitto/config/certs/client
      - ../certs/ca:/mosquitto/config/certs/ca
    tty: true
    network_mode: "service:broker"

networks:
  net:
    driver: bridge
    ipam:
      driver: default
      config:
        - subnet: 192.168.11.0/24

```

#### 1. Compose It All

```sh
docker-compose up --build
```

#### 2. Publisher Client

```sh
docker-compose exec pub sh
ifconfig
mosquitto_pub -d -h broker -p 8883 --cafile /mosquitto/config/certs/ca/ca.crt --cert /mosquitto/config/certs/client/client.crt --key /mosquitto/config/certs/client/client.key -t 'sample-topics' -m 'Hello from publisher'
```

#### 3. Subscriber Client

```sh
docker-compose exec sub sh
ifconfig
mosquitto_sub -d -h broker -p 8883 --cafile /mosquitto/config/certs/ca/ca.crt --cert /mosquitto/config/certs/client/client.crt --key /mosquitto/config/certs/client/client.key -t 'sample-topics'
```


<!-- <video src="img/20240624_tlsonly.mov" controls="true"></video> -->

![img](img/20240624_tlsonly_pic.png)

### Talk with Ogawa Kun and Kakoi Kun
- Resolver
  - Tells a client where to connect
    - VLAN: hostname
    - Localhost: port 
  - Connections
    - Periodic: Client-subscribe, resolver-publish
    - On-demand: Client-request, resolver-response
  - Number of hops - configurable, need to be checked
  - Opens only the first. Opens the second after a successful publish to the first
  - On TLS
- Postbox
  - Client auth: Easier hash(topic name & client key) as topic name & destination knowledge
  - Entities
    - VLAN: Docker container
    - Localhost: python process
  - No TLS

### Looking back the ideas...
- Answers as normal on every port possible using eBPF? -> No.
- VM Instance - too costy, go with just python packet handovering -> Changed.
- Hash as a topic name in a publish packet and no tls -> reduces crypto usage -> GOOD
- Port changing & calculation method - to be discussed -> no calculation, resolver will resolve

## 2024/06/30

### eBPF-enabled broker container
Using alpine:3.20.1 instead of 3.18, since it's the latest. Renaming of linux kernel headers and modules is needed, since the container kernel is of linuxkit but linux-lts-dev gets a general lts modules.
```dockerfile
FROM alpine:3.20.1

# Install mosquitto
RUN apk update && \
    apk add --no-cache mosquitto=2.0.18-r0 python3 bcc-tools linux-lts-dev

RUN ln -s $(ls /lib/modules) /lib/modules/$(uname -r)

CMD mosquitto -c /mosquitto/config/mosquitto.conf

# To test: /usr/share/bcc/tools/execsnoop
```

## 2024/07/02
### MTD Publish implemented in python
broker
```sh
docker exec -it hopper-label-broker-1 sh
python3 /mosquitto/mtd.py
```
subscriber
```sh
docker exec -it hopper-label-broker-1 sh # since mosquitto broker is accessible only from localhost, logs in as the broker for now
apk add mosquitto-clients
mosquitto_sub -p 11883 -t 'sample-topics'
```
publisher
```sh
docker exec -it hopper-label-pub-1 sh
rm -rf /mosquitto/topic_names
python3 /mosquitto/publisher.py broker 8883 sample-topics
mosquitto_pub -h broker -p 1883 -t 3R@ccZO@yWZXjhJz0Q== -m 'Hello MTD!'
```
```python
#common.py
from ssl import create_default_context, Purpose
from pathlib import Path
from string import punctuation
from base64 import b64encode, b64decode
from datetime import datetime

# Configuration settings
PORT_BROKER = 11883
RANDOMIZED_TOPIC_NAME_LENGTH = 11
NUM_RANDOMIZED_TOPIC_NAMES = 12
FETCH_LABEL = 'mqtt-mtd-hopping-label:'

BROKER_OUTPUT_DIRECTORY = Path("/mosquitto/topic_names")
PUBLISHER_OUTPUT_DIRECTORY = Path("/mosquitto/topic_names")

# Server addresses
SERVER_ADDRESS_8883 = ('broker', 8883)
SERVER_ADDRESS_1883 = ('broker', 1883)

# SSL/TLS Configuration
CA_FILE = "/mosquitto/config/certs/ca/ca.crt"
CERT_FILE = "/mosquitto/config/certs/broker/broker.crt"
KEY_FILE = "/mosquitto/config/certs/broker/broker.key"
CLIENT_CERT_FILE = "/mosquitto/config/certs/client/client.crt"
CLIENT_KEY_FILE = "/mosquitto/config/certs/client/client.key"

# Packet Types
PACKET_TYPES = [
    'RESRVED', 'CONNECT', 'CONNACK', 'PUBLISH', 'PUBACK_', 'PUBREC_',
    'PUBREL_', 'PUBCOMP', 'SUBSCRB', 'SUBACK_', 'UNSUBSC', 'UNSUBAC',
    'PINGREQ', 'PINGRSP', 'DISCNCT', 'AUTH___'
]

def is_ascii_printable(data: bytes) -> bool:
    try:
        decoded = data.decode('ascii')
        return all(char.isalnum() or char in ' ' + punctuation for char in decoded)
    except UnicodeDecodeError:
        return False

def b64decode_mqttsafe(bs: bytes) -> bytes:
    return b64decode(bs, altchars=b'!@')

def b64encode_mqttsafe(bs: bytes) -> bytes:
    return b64encode(bs, altchars=b'!@')

def print_hex(bs: bytes) -> str:
    return ' '.join(f"{b:02X}" for b in bs)

def print_packet(inout_spec: str, opponent: str, my_port: int, content: bytes) -> None:
    if inout_spec not in ('from', 'to'):
        print('Invalid inout_spec')
        return

    packet_type = 'UDEFND'
    message = f'len={len(content)}'

    if len(content) > 1:
        packet_type = PACKET_TYPES[(content[0] & 0xF0) >> 4]

    if len(content) > 4 and content[3] > 0 and packet_type == 'PUBLISH':
        len_topic_name = content[3]
        if len(content) >= 4 + len_topic_name:
            topic_name = content[4:4 + len_topic_name]
            topic_str = topic_name.decode() if is_ascii_printable(topic_name) else print_hex(topic_name)
            message += f", topic name: \"{topic_str}\""

    print(f"{datetime.now().ctime()} | {opponent}{'=>' if inout_spec == 'from' else '<='}:{my_port} [{packet_type}] {print_hex(content) if len(content) > 0 else ' (zero byte)'} ({message})")
```
```python
#mtd.py
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
```
```python
#publisher.py
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
```
```dockerfile
# broker/dockerfile
FROM alpine:3.20.1

RUN apk update && \
    apk add --no-cache mosquitto=2.0.18-r0 python3

RUN echo "export PS1='\u@\h:\w\$ '" > ~/.profile

CMD mosquitto -c /mosquitto/config/mosquitto.conf
```
```dockerfile
# client/dockerfile
FROM alpine:3.20.1

# Install mosquitto-clients
RUN apk update && \
    apk add --no-cache mosquitto-clients=2.0.18-r0 python3

RUN echo "export PS1='\u@\h:\w\$ '" > ~/.profile
```
```yaml
# docker-compose.yml
services:
  # Broker
  broker:
    build:
      context: ./broker
    image: mqtt-mtd/hopper-label/broker
    privileged: true
    volumes:
      - ./broker/topic_names:/mosquitto/topic_names
      - ./broker/mosquitto.conf:/mosquitto/config/mosquitto.conf
      - ./py/broker-mtd.py:/mosquitto/mtd.py
      - ./py/common.py:/mosquitto/common.py
      - ../certs/broker:/mosquitto/config/certs/broker
      - ../certs/ca:/mosquitto/config/certs/ca
    hostname: broker
    tty: true
    stdin_open: true
    restart: always
    networks:
      - net

  # Publisher
  pub:
    build:
      context: ./client
    image: mqtt-mtd/hopper-label/client
    volumes:
      - ./py/common.py:/mosquitto/common.py
      - ./py/publisher.py:/mosquitto/publisher.py
      - ../certs/client:/mosquitto/config/certs/client
      - ../certs/ca:/mosquitto/config/certs/ca
    hostname: publisher
    tty: true
    networks:
      - net

  # Subscriber
  sub:
    build:
      context: ./client
    image: mqtt-mtd/hopper-label/client
    volumes:
      - ../certs/client:/mosquitto/config/certs/client
      - ../certs/ca:/mosquitto/config/certs/ca
    tty: true
    network_mode: "service:broker"

networks:
  net:
    driver: bridge
    ipam:
      driver: default
      config:
        - subnet: 192.168.11.0/24
```

## 2024/07/03

### Create SAN-enabled certificates for golang tls x509
```sh
cd code/certs/ca
openssl req -new -x509 -days 365 -keyout ca-sans.key -out ca-sans.crt -subj '/C=JP' -addext 'subjectAltName = DNS:server'
# passphrase "mqttca"
cd ../broker
openssl req -out broker-sans.csr -key broker.key -new -subj '/C=JP'
openssl x509 -req -in broker-sans.csr -CA ../ca/ca-sans.crt -CAkey ../ca/ca-sans.key -CAcreateserial -out broker-sans.crt -days 100 -extensions v3_ext -extfile <(printf "[v3_ext]\nsubjectAltName=DNS:broker")
cd ../client
openssl req -out client-sans.csr -key client.key -new -subj '/C=JP'
openssl x509 -req -in client-sans.csr -CA ../ca/ca-sans.crt -CAkey ../ca/ca-sans.key -CAcreateserial -out client-sans.crt -days 100 -extensions v3_ext -extfile <(printf "[v3_ext]\nsubjectAltName=DNS:localhost")
```

### Migrate to Golang
```go
// go/broker/broker.go
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/kken7231/research-mqtt-mtd/code/hopper-label/common"
)

var (
	TOKENS      = make([][]byte, 0)
	TOPIC_NAMES = make([][]byte, 0)
	mu          sync.Mutex
)

func isTwoBytesEqual(a []byte, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	for i := len(a) - 1; i >= 0; i-- {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func registerCurrentToken(topicName []byte, token []byte) {
	TOKENS = append(TOKENS, token)
	TOPIC_NAMES = append(TOPIC_NAMES, topicName)
}

func updateCurrentToken(topicName []byte, newToken []byte) bool {
	for i, name := range TOPIC_NAMES {
		if isTwoBytesEqual(name, topicName) {
			TOKENS[i] = newToken
			return true
		}
	}
	return false
}

func revokeCurrentToken(token []byte) bool {
	for i, name := range TOKENS {
		if isTwoBytesEqual(name, token) {
			TOKENS[i] = TOKENS[len(TOKENS)-1]
			TOKENS = TOKENS[:len(TOKENS)-1]

			TOPIC_NAMES[i] = TOPIC_NAMES[len(TOPIC_NAMES)-1]
			TOPIC_NAMES = TOPIC_NAMES[:len(TOPIC_NAMES)-1]
			return true
		}
	}
	return false
}

func getTopicNameFromCurrentToken(token []byte) ([]byte, bool) {
	for i, name := range TOKENS {
		if isTwoBytesEqual(name, token) {
			return TOPIC_NAMES[i], true
		}
	}
	return nil, false
}

func decodeIfB64(token []byte) []byte {
	if len(token)%4 == 0 {
		converted, err := common.B64EncodedStringToBytes(string(token))
		if err != nil {
			panic(err)
		}
		return converted
	} else {
		return token
	}
}

func initTLSConfig() *tls.Config {
	cert, err := tls.LoadX509KeyPair(common.BROKER_CERT_FILE, common.BROKER_KEY_FILE)
	if err != nil {
		panic(err)
	}

	caCert, err := os.ReadFile(common.CA_CERT_FILE)
	if err != nil {
		panic(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
}

func replaceTokenWithTopicName(packetData []byte, clientIP string) []byte {
	packetDataLen := len(packetData)
	if packetDataLen < 4 || common.PACKET_TYPES[packetData[0]&0xF0>>4] != "PUBLISH" || packetData[3] == 0 {
		panic("Cannot read its topic name")
	}

	tokenLen := int(packetData[3])
	if packetDataLen < 4+tokenLen {
		panic("Illegal packet, probably topic name length is wrong")
	}

	token := decodeIfB64(packetData[4 : 4+tokenLen])
	if len(token) != common.TOKEN_LEN {
		panic(fmt.Sprintf("Illegal token: %d", len(token)))
	}

	topicName, ok := getTopicNameFromCurrentToken(token)
	if !ok {
		sb := strings.Builder{}
		for _, token := range TOKENS {
			sb.WriteByte('[')
			sb.WriteString(common.BytesToB64EncodedString(token))
			sb.WriteByte(']')
		}
		panic(fmt.Sprintf("No topic found: %s", sb.String()))
	}

	topicNameLen := len(topicName)
	if topicNameLen > 0xFF {
		panic("Found a too long topic name")
	}

	filePath := fmt.Sprintf("%s/%s-%s", common.BROKER_OUTPUT_DIRECTORY, topicName, clientIP)
	if _, err := os.Stat(filePath); err == nil {
		storedTokens, err := os.ReadFile(filePath)
		if err != nil {
			panic(err)
		}

		updateCurrentToken(topicName, storedTokens[:common.TOKEN_LEN])

		storedTokensLen := len(storedTokens)
		if storedTokensLen < common.TOKEN_LEN*2 || storedTokensLen%common.TOKEN_LEN != 0 {
			os.Remove(filePath)
		} else {
			err = os.WriteFile(filePath, storedTokens[common.TOKEN_LEN:], os.ModePerm)
			if err != nil {
				panic(err)
			}
		}
	} else {
		revokeCurrentToken(token)
	}

	newPacketLen := int(packetData[2])<<8 + int(packetData[1]) - tokenLen + topicNameLen
	newPacketData := bytes.NewBuffer([]byte{})
	newPacketData.WriteByte(packetData[0])
	newPacketData.WriteByte(byte(newPacketLen & 0xFF))
	newPacketData.WriteByte(byte((newPacketLen >> 8) & 0xFF))
	newPacketData.WriteByte(byte(topicNameLen))
	newPacketData.Write(topicName)
	newPacketData.Write(packetData[4+tokenLen:])

	return newPacketData.Bytes()
}

func replaceTokenWithTopicNameIfPublish(packetData []byte, clientIP string) []byte {
	if len(packetData) > 4 && common.PACKET_TYPES[packetData[0]&0xF0>>4] == "PUBLISH" && packetData[3] > 0 {
		return replaceTokenWithTopicName(packetData, clientIP)
	}
	return packetData
}

func issueTokens(dist *bytes.Buffer, topicName []byte, clientIP string, tokenLen int, numOfTokens int) []byte {
	if tokenLen%4 == 0 {
		panic("Token must not be a multiple of 4 in order to be distinguished from base64 encoded string")
	}
	if numOfTokens < 0 {
		panic("Number of randoms must be positive")
	}

	// Open file
	topicClientSpecifier := fmt.Sprintf("%s-%s", string(topicName), clientIP)
	filePath := fmt.Sprintf("%s/%s", common.BROKER_OUTPUT_DIRECTORY, topicClientSpecifier)
	output, err := os.Create(filePath)
	if err != nil {
		panic(err)
	}
	defer func() {
		if err := output.Close(); err != nil {
			panic(err)
		}
	}()

	mu.Lock()
	defer mu.Unlock()

	timestamp := make([]byte, 8)
	randomPart := make([]byte, common.RANDOM_BYTES_LEN)

	binary.BigEndian.PutUint64(timestamp, uint64(time.Now().UnixNano()))
	timestamp = timestamp[:common.TIMESTAMP_LEN] // Ignores least significant bytes

	nRand, err := rand.Read(randomPart)
	if err != nil || nRand != common.RANDOM_BYTES_LEN {
		panic("Generation of random bytes failed")
	}
	firstToken := append(timestamp, randomPart...)
	output.Write(firstToken)
	dist.Write(firstToken)
	for i := 1; i < numOfTokens; i++ {
		nRand, err = rand.Read(randomPart)
		if err != nil || nRand != common.RANDOM_BYTES_LEN {
			panic("Generation of random bytes failed")
		}
		output.Write(timestamp)
		output.Write(randomPart)

		dist.Write(timestamp)
		dist.Write(randomPart)
	}
	return firstToken
}

func generate(dist *bytes.Buffer, topicName []byte, clientIP string, tokenLen int, numOfTokens int) {
	firstToken := issueTokens(dist, topicName, clientIP, tokenLen, numOfTokens)

	updated := updateCurrentToken(topicName, firstToken)
	if !updated {
		registerCurrentToken(topicName, firstToken)
	}
}

func handleTLSClientConnection(conn *tls.Conn, addr string) {
	fmt.Printf("TLS connection established from %s\n", addr)
	defer func() {
		conn.Close()
		fmt.Printf("TLS connection closed from %s\n", addr)
	}()

	// Receive from the client
	data := make([]byte, 1024)
	n, err := conn.Read(data)
	if err != nil && err != io.EOF {
		fmt.Printf("Error reading from %s: %v\n", addr, err)
		return
	}
	if n == 0 {
		return
	}
	packetData := data[:n]
	common.PrintPacket("incoming", conn, packetData)

	buf := bytes.NewBuffer([]byte{})

	// Generate tokens
	if bytes.HasPrefix(packetData, []byte(common.FETCH_LABEL)) {
		trueName := packetData[len(common.FETCH_LABEL):]
		if len(trueName) > 0 && !bytes.ContainsAny(trueName, "+#") {
			generate(buf, trueName, addr, common.TOKEN_LEN, common.NUM_TOKENS_PER_GENE)
		} else {
			fmt.Printf("Invalid topic name %s\n", trueName)
		}
	} else {
		fmt.Printf("No label %s\n", common.FETCH_LABEL)
	}
	_, err = conn.Write(buf.Bytes())

	// Send the responce back
	if err != nil {
		fmt.Printf("Error sending to %s: %v\n", addr, err)
	} else {
		common.PrintPacket("outgoing", conn, buf.Bytes())
	}
}

func handlePlainClientConnection(conn net.Conn, addr string) {
	fmt.Printf("Plain connection established from %s\n", addr)
	defer func() {
		conn.Close()
		fmt.Printf("Plain connection closed from %s\n", addr)
	}()

	brokerConn, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", common.PORT_BROKER))
	if err != nil {
		fmt.Printf("Error connecting to broker: %v\n", err)
		return
	}
	defer brokerConn.Close()

	for {
		// Receive from the client
		data := make([]byte, 1024)
		n, err := conn.Read(data)
		if err != nil && err != io.EOF {
			fmt.Printf("Error reading from %s: %v\n", addr, err)
			break
		}
		if n == 0 {
			break
		}
		packetData := data[:n]
		common.PrintPacket("incoming", conn, packetData)

		// Replace the token & pass it to the broker
		packetData = replaceTokenWithTopicNameIfPublish(packetData, addr)
		_, err = brokerConn.Write(packetData)
		if err != nil {
			fmt.Printf("Error sending to broker: %v\n", err)
			break
		}
		common.PrintPacket("outgoing", brokerConn, packetData)

		// Receive the response from the broker
		response := make([]byte, 1024)
		n, err = brokerConn.Read(response)
		if err != nil && err != io.EOF {
			fmt.Printf("Error reading from broker: %v\n", err)
			break
		}
		response = response[:n]
		common.PrintPacket("incoming", conn, response)

		// Pass the responce down to the client
		_, err = conn.Write(response)
		if err != nil {
			fmt.Printf("Error sending to %s: %v\n", addr, err)
			break
		}
		common.PrintPacket("outgoing", conn, response)
	}
}

func runServer(address string, useTLS bool) {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	fmt.Printf("Listening on %s (%s)\n", address, func() string {
		if useTLS {
			return "TLS"
		}
		return "Plain"
	}())

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("Error accepting connection: %v\n", err)
			continue
		}

		if useTLS {
			tlsConn := tls.Server(conn, initTLSConfig())
			go handleTLSClientConnection(tlsConn, conn.RemoteAddr().String())
		} else {
			go handlePlainClientConnection(conn, conn.RemoteAddr().String())
		}
	}
}

func main() {
	common.EnsureOutputDir(common.BROKER_OUTPUT_DIRECTORY)

	go runServer(common.SERVER_ADDRESS_8883, true)
	go runServer(common.SERVER_ADDRESS_1883, false)

	fmt.Println("TLS server and plain server are running in background threads.")

	select {} // keep the main function running
}
```
```go
// go/common/common.go
package common

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	DEBUG                   = true
	PORT_BROKER             = 11883
	NUM_TOKENS_PER_GENE     = 10
	TIMESTAMP_LEN           = 7
	TOKEN_LEN               = 11
	RANDOM_BYTES_LEN        = TOKEN_LEN - TIMESTAMP_LEN
	FETCH_LABEL             = "mqtt-mtd-hopping-label:"
	SERVER_ADDRESS_8883     = "broker:8883"
	SERVER_ADDRESS_1883     = "broker:1883"
	CA_CERT_FILE            = "/mosquitto/config/certs/ca/ca-sans.crt"
	BROKER_CERT_FILE        = "/mosquitto/config/certs/broker/broker-sans.crt"
	BROKER_KEY_FILE         = "/mosquitto/config/certs/broker/broker.key"
	CLIENT_CERT_FILE        = "/mosquitto/config/certs/client/client-sans.crt"
	CLIENT_KEY_FILE         = "/mosquitto/config/certs/client/client.key"
	BROKER_OUTPUT_DIRECTORY = "/mosquitto/topic_names/"
	CLIENT_OUTPUT_DIRECTORY = "/mosquitto/topic_names/"
)

var PACKET_TYPES = [16]string{"RESRVED", "CONNECT", "CONNACK", "PUBLISH", "PUBACK_", "PUBREC_", "PUBREL_", "PUBCOMP", "SUBSCRB", "SUBACK_", "UNSUBSC", "UNSUBAC", "PINGREQ", "PINGRSP", "DISCNCT", "AUTH___"}

func EnsureOutputDir(dirPath string) {
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		err = os.Mkdir(dirPath, os.ModePerm)
		if err != nil {
			panic(err)
		}
	}
}

func PrintPacket(inoutSpec string, conn net.Conn, content []byte) {
	if !DEBUG {
		return
	}

	if inoutSpec != "outgoing" && inoutSpec != "incoming" {
		fmt.Println("invalid inout_spec")
		return
	}
	packetType := ""
	message := fmt.Sprintf("len=%d", len(content))
	if len(content) > 1 {
		packetType = PACKET_TYPES[content[0]&0xF0>>4]
	}
	if len(content) > 4 && content[3] > 0 && packetType == "PUBLISH" {
		lenTopicName := content[3]
		if len(content) < 4+int(lenTopicName) {
			fmt.Println("Error decoding topic name")
		} else {
			message = fmt.Sprintf("topic name: \"%s\"", string(content[4:4+lenTopicName]))
		}
	}
	fmt.Printf("%s | %s%s:%s [%s] %s (%s)\n",
		time.Now().Format(time.RFC1123),
		conn.RemoteAddr(),
		func() string {
			if inoutSpec == "incoming" {
				return "=>"
			}
			return "<="
		}(),
		func() string {
			splitted := strings.Split(conn.LocalAddr().String(), ":")
			return splitted[len(splitted)-1]
		}(),
		packetType,
		hex.EncodeToString(content),
		message)
}

func BytesToEscapedString(bs []byte) string {
	sb := strings.Builder{}
	for _, b := range bs {
		sb.WriteString("\\x")
		if b < 0x10 {
			sb.WriteByte('0')
		}
		sb.WriteString(strconv.FormatUint(uint64(b), 16))
	}
	return sb.String()
}

func BytesToB64EncodedString(bs []byte) string {
	return base64.URLEncoding.EncodeToString(bs)
}

func B64EncodedStringToBytes(encoded string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(encoded)
}
```
```go
// go/publisher/publisher.go
package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kken7231/research-mqtt-mtd/code/hopper-label/common"
)

var (
	TOKENS            = make([][]byte, 0)
	TOPIC_NAMES       = make([][]byte, 0)
	OUTPUT_ONLY_TOKEN = false
	OUTPUT_B64        = false
)

func printIfNotOnly(format string, a ...any) {
	if !OUTPUT_ONLY_TOKEN {
		fmt.Printf(format, a...)
	}
}

func printPacketIfNotOnly(inoutSpec string, conn net.Conn, content []byte) {
	if !OUTPUT_ONLY_TOKEN {
		common.PrintPacket(inoutSpec, conn, content)
	}
}

func isValidHostname(hostname string) bool {
	if len(hostname) > 255 || len(hostname) == 0 {
		return false
	}
	if hostname[len(hostname)-1] == '.' {
		hostname = hostname[:len(hostname)-1]
	}
	for _, label := range strings.Split(hostname, ".") {
		if len(label) > 63 {
			return false
		}
		for _, char := range label {
			if !strings.Contains("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-", string(char)) {
				return false
			}
		}
	}
	return true
}

func isValidPort(port int) bool {
	return port >= 1 && port <= 65535
}

func isValidTopicName(topicName string) bool {
	if len(topicName) == 0 {
		return false
	}

	for _, char := range topicName {
		if char < 32 || char > 126 {
			return false
		}
	}
	return true
}

func connectTLS(host string, port uint16, topicName string) ([]byte, error) {
	defer func() {
		if r := recover(); r != nil {
			printIfNotOnly("Recovered in connectTLS: %v", r)
		}
	}()
	cert, err := tls.LoadX509KeyPair(common.CLIENT_CERT_FILE, common.CLIENT_KEY_FILE)
	if err != nil {
		panic(err)
	}

	caCert, err := os.ReadFile(common.CA_CERT_FILE)
	if err != nil {
		panic(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}

	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", host, port), config)
	if err != nil {
		fmt.Printf("Error connecting to TLS server: %v\n", err)
		return nil, err
	}
	defer conn.Close()

	data := []byte(fmt.Sprintf("%s%s", common.FETCH_LABEL, topicName))
	conn.Write(data)
	printPacketIfNotOnly("outgoing", conn, data)

	response := make([]byte, common.NUM_TOKENS_PER_GENE*common.TOKEN_LEN)
	n, err := conn.Read(response)
	if err != nil {
		fmt.Printf("Error receiving from TLS server: %v\n", err)
		return nil, err
	}
	response = response[:n]
	printPacketIfNotOnly("incoming", conn, response)

	err = storeTokens(topicName, response[common.TOKEN_LEN:])
	return response[:common.TOKEN_LEN], err
}

func storeTokens(topicName string, tokensToBeSaved []byte) error {
	if len(tokensToBeSaved) < common.TOKEN_LEN {
		panic("No data as randomized topic names")
	}
	filePath := filepath.Join(common.CLIENT_OUTPUT_DIRECTORY, fmt.Sprintf("%s-%s", topicName, time.Now().Format(time.RFC3339)))
	return os.WriteFile(filePath, tokensToBeSaved, os.ModePerm)
}

func popToken(host string, port uint16, trueName string) ([]byte, error) {
	filePath := filepath.Join(common.CLIENT_OUTPUT_DIRECTORY, fmt.Sprintf("%s:%d-%s", host, port, trueName))
	tokens, err := os.ReadFile(filePath)
	if err != nil {
		panic(err)
	}
	if len(tokens)%common.TOKEN_LEN != 0 || len(tokens) == 0 {
		fmt.Printf("%d %d\n", len(tokens), common.TOKEN_LEN)
		panic(fmt.Sprintf("Invalid File: %s", filePath))
	}
	if len(tokens) < common.TOKEN_LEN*2 {
		err = os.Remove(filePath)
	} else {
		err = os.WriteFile(filePath, tokens[common.TOKEN_LEN:], os.ModePerm)
	}
	return tokens[:common.TOKEN_LEN], err
}

func getToken(host string, port uint16, trueName string) ([]byte, error) {
	filePath := filepath.Join(common.CLIENT_OUTPUT_DIRECTORY, fmt.Sprintf("%s:%d-%s", host, port, trueName))
	if _, err := os.Stat(filePath); err == nil {
		return popToken(host, port, trueName)
	}
	return connectTLS(host, port, trueName)
}

func main() {
	common.EnsureOutputDir(common.CLIENT_OUTPUT_DIRECTORY)

	only := flag.Bool("only", false, "Prints only the token if true, otherwise prints all")
	b64 := flag.Bool("b64", false, "Prints the b64-encoded token if true, otherwise prints all")
	host := flag.String("host", "", "Hostname of the MQTT server")
	port_int := flag.Int("port", 0, "Port number of the MQTT server")
	topic := flag.String("topic", "", "MQTT topic name")
	flag.Parse()

	// Validate inputs
	if !isValidHostname(*host) {
		fmt.Println("Invalid hostname")
	} else if !isValidPort(*port_int) {
		fmt.Println("Invalid port number")
	} else if !isValidTopicName(*topic) {
		fmt.Println("Invalid topic name. It must be an ASCII string with printable characters.")
	} else {
		OUTPUT_ONLY_TOKEN = *only
		OUTPUT_B64 = *b64
		// Proceed with connection and topic name fetching
		retrieved, err := getToken(*host, uint16(*port_int), *topic)
		if err != nil {
			fmt.Println("Error found")
			os.Exit(-1)
		} else if OUTPUT_ONLY_TOKEN {
			if OUTPUT_B64 {
				fmt.Print(common.BytesToB64EncodedString(retrieved))
			} else {
				fmt.Print(common.BytesToEscapedString(retrieved))
			}
		} else {
			if OUTPUT_B64 {
				fmt.Printf("First Token: %s\n", common.BytesToB64EncodedString(retrieved))
			} else {
				fmt.Printf("First Token: %s\n", common.BytesToEscapedString(retrieved))
			}
		}
	}
}
```
```dockerfile
# broker/Dockerfile
FROM alpine:3.20.1

RUN apk update && \
    apk add --no-cache mosquitto=2.0.18-r0 go=1.22.4-r0

RUN echo "export PS1='\u@\h:\w\$ '" > ~/.profile

CMD mosquitto -c /mosquitto/config/mosquitto.conf
```
```dockerfile
# client/Dockerfile
FROM alpine:3.20.1

# Install mosquitto-clients
RUN apk update && \
    apk add --no-cache mosquitto-clients=2.0.18-r0 go=1.22.4-r0

RUN echo "export PS1='\u@\h:\w\$ '" > ~/.profile
```
```yaml
# docker-compose.yml
services:
  # Broker
  broker:
    build:
      context: ./broker
    image: mqtt-mtd/hopper-label/broker
    privileged: true
    volumes:
      - ./py:/mosquitto/py:ro
      - ./go:/mosquitto/go:ro
      - ./broker/mosquitto.conf:/mosquitto/config/mosquitto.conf:ro
      - ../certs/broker:/mosquitto/config/certs/broker:ro
      - ../certs/ca:/mosquitto/config/certs/ca:ro
    hostname: broker
    tty: true
    stdin_open: true
    restart: always
    networks:
      - net

  # Publisher
  pub:
    build:
      context: ./client
    image: mqtt-mtd/hopper-label/client
    volumes:
      - ./py:/mosquitto/py:ro
      - ./go:/mosquitto/go:ro
      - ../certs/client:/mosquitto/config/certs/client:ro
      - ../certs/ca:/mosquitto/config/certs/ca:ro
    hostname: publisher
    tty: true
    networks:
      - net

  # Subscriber
  sub:
    build:
      context: ./client
    image: mqtt-mtd/hopper-label/client
    volumes:
      - ../certs/client:/mosquitto/config/certs/client:ro
      - ../certs/ca:/mosquitto/config/certs/ca:ro
    tty: true
    network_mode: "service:broker"

networks:
  net:
    driver: bridge
    ipam:
      driver: default
      config:
        - subnet: 192.168.11.0/24
```

```sh
rm -rf /mosquitto/topic_names
mosquitto_pub -h broker -p 1883 -m "hello:) $(date)" -t $(go run github.com/kken7231/research-mqtt-mtd/code/hopper-label/publisher -only -b64 -host broker -port 8883 -topic sample-topics)
```

## 2024/07/07

### Command samples
```sh
mosquitto_sub -h broker -p 1883 -V mqttv5 -t $(go run github.com/kken7231/research-mqtt-mtd/code/hopper-label/subscriber -only -b64 -ntokens 1 -host broker -port 8883 -topic sample-topics)

go run github.com/kken7231/research-mqtt-mtd/code/hopper-label/publisher -b64 -host broker -port 8883 -ntokens 2 -topic sample-topics
go run github.com/kken7231/research-mqtt-mtd/code/hopper-label/subscriber -b64 -host broker -port 8883 -ntokens 2 -topic sample-topics

go run github.com/kken7231/research-mqtt-mtd/code/hopper-label/broker

mosquitto_pub -h broker -p 1883 -m "hello temp:) $(date)" -t $(go run github.com/kken7231/research-mqtt-mtd/code/hopper-label/publisher -only -b64 -ntokens 3 -host broker -port 8883 -topic sample/temp)
mosquitto_pub -h broker -p 1883 -m "hello humid:) $(date)" -t $(go run github.com/kken7231/research-mqtt-mtd/code/hopper-label/publisher -only -b64 -ntokens 3 -host broker -port 8883 -topic sample/humid)
mosquitto_sub -h broker -p 1883 -V mqttv5 -t $(go run github.com/kken7231/research-mqtt-mtd/code/hopper-label/subscriber -only -b64 -ntokens 3 -host broker -port 8883 -topic sample/temp)
mosquitto_sub -h broker -p 1883  -t $(go run github.com/kken7231/research-mqtt-mtd/code/hopper-label/subscriber -only -b64 -ntokens 3 -host broker -port 8883 -topic sample/temp)
```

### Future Work Idea
1. Better conformance to the specification
  - Max packet size limitation check
2. Better connection manipulation
3. Error handling

### Current problems
1. Topic names in server-to-client publishes are not tokenized => Can be secured additionally
2. Some mqtt clients automatically retry a subscribe request with the same token. mosquitto_sub: yes
3. Thorough testcases needed

### Testing
```sh
mkdir test; cd test
go install github.com/testcontainers/testcontainers-go@latest
```
