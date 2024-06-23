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

