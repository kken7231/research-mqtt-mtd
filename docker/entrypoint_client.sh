#!/bin/sh

case "$RUNNER_TYPE" in
    "once")
        export TOKENMGR_TOML="/mqttmtd/conf/tokenmgr_once.toml"
        ;;

    "server")
        export TOKENMGR_TOML="/mqttmtd/conf/tokenmgr_server.toml"
        ;;

    *)
        echo "Error: Unrecognizable runner type RUNNER_TYPE=\"$RUNNER_TYPE\"" >&2 # Send error to standard error
        exit 255
        ;;
esac


case "$PROTOCOL" in
    "plain")
        export SERVER_PORT=1883
        ;;

    "tls")
        export SERVER_PORT=8883
       ;;

    "websocket")
        export SERVER_PORT=8080
        ;;

    "wss")
        export SERVER_PORT=8081
        ;;

    *)
        echo "Error: Unrecognizable protocol PROTOCOL=\"$PROTOCOL\"" >&2 # Send error to standard error
        exit 255
        ;;

esac

echo "Runner type: $RUNNER_TYPE"
echo "Protocol:    $PROTOCOL"
echo "TOKENMGR_TOML: $TOKENMGR_TOML"
echo "Client:             $CLIENT_NAME"
echo "Port:               $SERVER_PORT"
echo "mosquitto tls args: \"$MOSQUITTO_TLS_ARGS_EMPTY_IF_BROKER_IS_PLAIN\""

if [ "$RUNNER_TYPE" = "server" ]; then
  echo "Starting server..."
  /mqttmtd/bin/tokenmgr --conf $TOKENMGR_TOML 2>&1 | awk '{ print "(tokenmgr) ", $0 }' &
  TOKENMGR=$!
  echo "Mosquitto started with PID ${TOKENMGR}"
fi

wait -n
