# MQTT-MTD

## Preparation

### Docker Image - Server
Server consists of these services:
- Auth Server
- MQTT Interface
- Two Mosquitto Servers (Plain and TLS)

## Testing Procedure

### Before

1. Run docker-compose in ./database
```sh
cd database
docker-compose up --build
```

2. Run server with ./shell/run_server_macos
```sh
cd shell
./run_server_macos
```

3. Run arduino logging program on an ESP32C3

4. Check that grafana and other services are working well

5. Start Wireshark recording

6. Flash the testing binary to an ESP32C3 and monitor it, use Ctrl+T then Ctrl+L to output log file

### After
1. Stop Wireshark and save the recorded packets

2. Disconnect power logger

3. Retrieve log from Docker for database compose

4. Copy and store sqlite.db