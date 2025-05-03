#!/bin/sh

mosquitto_pub -h server -p $SERVER_PORT -t "/topics/sample" -m "simple_publish_plain_1883"