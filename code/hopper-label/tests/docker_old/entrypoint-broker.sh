#!/bin/sh
mosquitto -c /mosquitto/config/confs/mosquitto-plain-localonly_11883.conf &
mosquitto -c /mosquitto/config/confs/mosquitto-tls_8883.conf &
mosquitto -c /mosquitto/config/confs/mosquitto-plain_1883.conf
