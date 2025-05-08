#!/bin/sh

case "$PROTOCOL" in
    "plain")
        SERVER_PORT=1883
        ;;

    "tls")
        SERVER_PORT=8883
        ;;

    "websocket")
        SERVER_PORT=8080
        ;;

    "wss")
        SERVER_PORT=8081
        ;;

    *)
        echo "Error: Unrecognizable protocol PROTOCOL=\"$PROTOCOL\"" >&2 # Send error to standard error
        exit 255
        ;;

esac

echo "Protocol: $PROTOCOL"
echo "Client:             $CLIENT_NAME"
echo "Port:               $SERVER_PORT"
echo "mosquitto tls args: \"$MOSQUITTO_TLS_ARGS_EMPTY_IF_BROKER_IS_PLAIN\""
echo "Subscribing to Broker in 10 sec..."
echo ""

sleep 10

if [ "$PROTOCOL" = "plain" ] || [ "$PROTOCOL" = "websocket" ]; then
  # No TLS arguments needed
  mosquitto_sub -h server -p "$SERVER_PORT" -t "#"

elif [ "$PROTOCOL" = "tls" ] || [ "$PROTOCOL" = "wss" ]; then
  # Include TLS arguments
  mosquitto_sub \
    -h server -p "$SERVER_PORT" \
    --tls-version tlsv1.3 \
    --cafile "/certs/ca/ca.crt" \
    --cert "/certs/clients/${CLIENT_NAME}.crt" \
    --key "/certs/clients/${CLIENT_NAME}.pem" \
    -t "#"
fi