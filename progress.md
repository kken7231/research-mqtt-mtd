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
FROM alpine:3.18

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
FROM alpine:3.18

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
  libllvm14 llvm-14-dev libclang-14-dev libpolly-14-dev python3 zlib1g-dev libelf-dev libfl-dev python3-setuptools \
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

### Ideas

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
FROM alpine:3.18

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
      - ./certs/broker:/mosquitto/config/certs/broker
      - ./certs/ca:/mosquitto/config/certs/ca
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
      - ./certs/client:/mosquitto/config/certs/client
      - ./certs/ca:/mosquitto/config/certs/ca
    hostname: publisher
    tty: true
    networks:
      - net

  # Subscriber
  sub:
    build:
      context: ../../mosquitto-cli
    volumes:
      - ./certs/client:/mosquitto/config/certs/client
      - ./certs/ca:/mosquitto/config/certs/ca
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


<video src="img/20240624_tlsonly.mov" controls="true"></video>

![img](img/20240624_tlsonly_pic.png)
