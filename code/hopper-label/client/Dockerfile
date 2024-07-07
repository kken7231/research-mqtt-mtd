FROM alpine:3.20.1

# Install mosquitto-clients
RUN apk update && \
    apk add --no-cache mosquitto-clients=2.0.18-r0 go=1.22.4-r0

RUN echo "export PS1='\u@\h:\w\$ '" > ~/.profile