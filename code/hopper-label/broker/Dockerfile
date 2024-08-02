FROM alpine:3.20.1

RUN apk update && \
    apk add --no-cache mosquitto=2.0.18-r0 go=1.22.4-r0

COPY --chmod=444 ../certs/ca /mosquitto/config/certs/ca
COPY --chmod=444 ../certs/broker /mosquitto/config/certs/broker

COPY --chmod=444 ./mosquitto.conf /mosquitto/config/mosquitto.conf

COPY --chmod=444 ../go/go.work /mosquitto/go/go.work
COPY --chmod=444 ../go/common /mosquitto/go/common
COPY --chmod=444 ../go/broker /mosquitto/go/broker

CMD mosquitto -c /mosquitto/config/mosquitto.conf