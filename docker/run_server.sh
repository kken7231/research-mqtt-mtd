#!/bin/zsh

# remove if exists
docker remove mqttmtd-server

# Build an image without cache
docker build --no-cache -t mqttmtd-server-image:latest -f Dockerfiles/Dockerfile.server ../

# Run an container
docker run --name mqttmtd-server -p 11883:11883 -p 3000:3000 -e PROTOCOL=${PROTOCOL} mqttmtd-server-image:latest