FROM alpine:3.20.1

# Install mosquitto
RUN apk update && \
    apk add --no-cache mosquitto=2.0.18-r0

EXPOSE 1883

CMD mosquitto -c /mosquitto/config/mosquitto.conf