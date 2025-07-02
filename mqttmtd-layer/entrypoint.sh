#!/bin/sh

# create certs
/mqttmtd/bin/testing certgen --conf /mqttmtd/conf/certgen.toml --server-cn "${HOST_NAME}" --output-dir /certs

sleep 1

/mqttmtd/bin/mqttmtd-authserver --conf /mqttmtd/conf/authserver.toml 2>&1 | awk '{ print "(authserver)    ", $0 }' &
AUTH_SERVER_PID=$!
echo "Auth server started with PID ${AUTH_SERVER_PID}"

sleep 1

/mqttmtd/bin/mqttinterface --conf /mqttmtd/conf/mqttinterface.toml 2>&1 | awk '{ print "(mqttinterface) ", $0 }' &
MQTT_INTERFACE_PID=$!
echo "MQTT interface started with PID ${MQTT_INTERFACE_PID}"

# Kept for Wireshark monitoring
#
#TCPDUMP_PID=""
#if [ "${HOST_TCPDUMP_LISTEN_PORT}" != "" ]; then
#  tcpdump -i any -U -s0 -w - "(host client1 or host 127.0.0.1) and not arp" | nc host.docker.internal "${HOST_TCPDUMP_LISTEN_PORT}" &
#  TCPDUMP_PID=$!
#  echo "Sending out tcpdump tracking..."
#fi

echo ""
echo "Entrypoint: Setup complete. Marking application as ready."
touch "/mqttmtd/server_ready"

wait ${AUTH_SERVER_PID} ${MQTT_INTERFACE_PID} # ${TCPDUMP_PID}
