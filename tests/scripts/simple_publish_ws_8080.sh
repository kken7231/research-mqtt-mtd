#!/bin/sh

mosquitto_pub -h server -p 8080 -t "/topics/sample" -m "simple_publish_ws_8080"