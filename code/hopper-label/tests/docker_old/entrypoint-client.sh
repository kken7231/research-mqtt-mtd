#!/bin/sh
sleep 5

cd /mosquitto/go/tests/T01_plainPub && go build . && ./T01_plainPub

exit