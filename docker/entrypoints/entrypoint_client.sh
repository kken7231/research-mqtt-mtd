#!/bin/sh

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

export TOKENMGR_TOML="/mqttmtd/conf/tokenmgr.toml"

echo "Runner type: $RUNNER_TYPE"
echo "Protocol:    $PROTOCOL"
echo "TOKENMGR_TOML: $TOKENMGR_TOML"
echo "Client:             $CLIENT_NAME"
echo "Port:               $SERVER_PORT"
echo "mosquitto tls args: \"$MOSQUITTO_TLS_ARGS_EMPTY_IF_BROKER_IS_PLAIN\""

exec "$@"
