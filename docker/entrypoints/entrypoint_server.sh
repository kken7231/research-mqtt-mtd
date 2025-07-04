#!/bin/sh

case "$PROTOCOL" in
    "plain")
        mqttinterface_toml="/mqttmtd/conf/mqttinterface_plain.toml"
        mosquitto_conf="/mosquitto/conf/plain.conf"
        ;;

    "tls")
        mqttinterface_toml="/mqttmtd/conf/mqttinterface_tls.toml"
        mosquitto_conf="/mosquitto/conf/tls.conf"
        ;;

    "websocket")
        mqttinterface_toml="/mqttmtd/conf/mqttinterface_websocket.toml"
        mosquitto_conf="/mosquitto/conf/websocket.conf"
        ;;

    "wss")
        mqttinterface_toml="/mqttmtd/conf/mqttinterface_wss.toml"
        mosquitto_conf="/mosquitto/conf/wss.conf"
        ;;

    *)
        echo "Error: Unrecognizable protocol PROTOCOL=\"$PROTOCOL\"" >&2
        exit 255
        ;;

esac

echo "Protocol: $PROTOCOL"
echo "MQTT Interface toml: $mqttinterface_toml"
echo "Mosquitto conf:      $mosquitto_conf"
echo "Starting server..."
echo ""

mosquitto -v -c $mosquitto_conf 2>&1 | awk '{ print "(mosquitto) ", $0 }' &
MOSQUITTO=$!
echo "Mosquitto started with PID ${MOSQUITTO}"

sleep 1

/mqttmtd/bin/mqttmtd-authserver --conf /mqttmtd/conf/authserver.toml 2>&1 | awk '{ print "(authserver) ", $0 }' &
AUTH_SERVER_PID=$!
echo "Auth server started with PID ${AUTH_SERVER_PID}"

sleep 1

/mqttmtd/bin/mqttinterface --conf $mqttinterface_toml 2>&1 | awk '{ print "(mqttinterface) ", $0 }' &
MQTT_INTERFACE_PID=$!
echo "MQTT interface started with PID ${MQTT_INTERFACE_PID}"

TCPDUMP_PID=""
if [ "${HOST_TCPDUMP_LISTEN_PORT}" != "" ]; then
  tcpdump -i any -U -s0 -w - "(host client1 or host 127.0.0.1) and not arp" | nc host.docker.internal "${HOST_TCPDUMP_LISTEN_PORT}" &
  TCPDUMP_PID=$!
  echo "Sending out tcpdump tracking..."
fi

echo ""
echo "Entrypoint: Setup complete. Marking application as ready."
touch "/mqttmtd/server_ready"

wait ${MOSQUITTO} ${AUTH_SERVER_PID} ${MQTT_INTERFACE_PID} ${TCPDUMP_PID}
