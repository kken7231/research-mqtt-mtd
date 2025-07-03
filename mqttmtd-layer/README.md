# MQTTMTD Layer

_MQTTMTD Layer_ is a bundle of MQTTMTD-specific components, namely the _Auth Server_ and the _MQTT Interface_. They do
encoding and decoding of MQTTMTD packets, not only issuance of token sets.

## Command to run

1. Run MQTT Server on the host.</br>
   ```shell
   mosquitto # for example
   ```

2. Launch docker compose
   ```shell
   docker compose up --build
   ```
   \* there are a few parameters to set in docker-compose.yaml
    - HOST_NAME: Hostname of the host machine
    - MQTT Broker port

3. Now system translates MQTT-MTD. MQTT Interface port is the port to send packets.

## Configs

Please refer to [#Configs](../README.md#configurations).