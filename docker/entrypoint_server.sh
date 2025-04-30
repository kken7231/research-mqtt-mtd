#!/bin/sh

# Start the first process, redirect stderr to stdout (2>&1),
# pipe stdout to sed to add prefix, and run in background (&)
#/mqttmtd/bin/mqttmtd-authserver 2>&1 | sed 's/^/(authserver) /' &
#AUTH_SERVER_PID=$!
#echo "Auth server started with PID ${AUTH_SERVER_PID}" # Optional log message

/mqttmtd/bin/mqttinterface 2>&1 | sed 's/^/(mqttinterface) /' &
MQTT_INTERFACE_PID=$!
echo "MQTT interface started with PID ${MQTT_INTERFACE_PID}" # Optional log message

wait -n
