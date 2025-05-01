#!/bin/sh

case "$RUNNER_TYPE" in
    "once")
        mqttinterface_toml="/mqttmtd/conf/mqttinterface_plain.toml"
        mosquitto_conf="/mosquitto/conf/plain.conf"
        ;;

    "server")
        mqttinterface_toml="/mqttmtd/conf/mqttinterface_tls.toml"
        mosquitto_conf="/mosquitto/conf/tls.conf"
        ;;

    *)
        echo "Error: Unrecognizable runner type RUNNER_TYPE=\"$PROTOCOL\"" >&2 # Send error to standard error
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

wait -n
