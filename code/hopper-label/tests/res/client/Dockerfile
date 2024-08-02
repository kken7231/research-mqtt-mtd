FROM alpine:3.20.1

RUN apk update && \
    apk add --no-cache mosquitto-clients=2.0.18-r0 go=1.22.4-r0

COPY ../certs/ca /mosquitto/config/certs/ca
COPY ../certs/client /mosquitto/config/certs/client

COPY ./mosquitto.conf /mosquitto/config/mosquitto.conf

COPY ../go/go.work /mosquitto/go/go.work
COPY ../go/common /mosquitto/go/common
COPY ../go/publisher /mosquitto/go/publisher
COPY ../go/subscriber /mosquitto/go/subscriber
