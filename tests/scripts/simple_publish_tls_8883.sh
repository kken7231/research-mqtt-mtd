#!/bin/sh

mosquitto_pub -h server -p 8883 -t "/topics/sample" -m "simple_publish_tls_8883" --tls-version tlsv1.3 --cafile "/certs/ca/ca.crt" --cert "/certs/clients/client1.crt" --key "/certs/clients/client1.pem"