# MQTT & MTD

## 2024/06/20

### Paper Reading

- "Securing MQTT Ecosystem: Exploring Vulenrabilities, Mitigations, and Future Trajectories"

### Slide Making

- Summarize the current status on what I recognize
  ![slide](img/20240624_suggest.png)

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

<video src="img/20240625_first_proto.mov" controls="true"></video>
