#!/bin/sh

# Function to prepend service name to each line of log
prepend_service_name() {
  while IFS= read -r line; do
    echo "$1| $line"
  done
}
# Start the MQTT server and log its output
mosquitto -c /mosquitto/config/mosquitto.conf 2>&1 | prepend_service_name "mosquitto     " >> /mqttmtd/logs/combined.log &

sleep 1

# Start the auth server and log its output
/mqttmtd/authserver 2>&1 | prepend_service_name "authserver    " >> /mqttmtd/logs/combined.log &

# Start the MQTT interface and log its output
/mqttmtd/mqttinterface 2>&1 | prepend_service_name "mqttinterface " >> /mqttmtd/logs/combined.log &

# Tail the combined log file to keep the container running and display the logs
tail -f /mqttmtd/logs/combined.log