#!/bin/bash

# Exit on any error
set -e

# Directories
CERTS_DIR="./certs"

# Parse command-line arguments
while getopts "c:" opt; do
  case $opt in
    c) CERTS_DIR="$OPTARG" ;;
    \?) echo "Invalid option -$OPTARG" >&2; exit 1 ;;
  esac
done

# Directories
CA_CERTS_DIR="$CERTS_DIR/ca"
SERVER_CERTS_DIR="$CERTS_DIR/server"
rm -rf "$CERTS_DIR"
mkdir -p "$CA_CERTS_DIR" "$SERVER_CERTS_DIR"

# Configuration Files
CA_CONFIG="./conf/ca.conf"
SERVER_CONFIG="./conf/server.conf"

# CA File Paths
CA_KEY="$CA_CERTS_DIR/ca.key"
CA_CERT="$CA_CERTS_DIR/ca.crt"
CA_PASSWORD="mqttca"

# Server File Paths
SERVER_KEY="$SERVER_CERTS_DIR/server.key"
SERVER_CSR="$SERVER_CERTS_DIR/server.csr"
SERVER_CERT="$SERVER_CERTS_DIR/server.crt"
SERVER_PASSWORD=""

# Generate CA key
openssl genpkey -algorithm RSA -out "$CA_KEY" -pass pass:"$CA_PASSWORD" # -aes256
# Generate CA certificate
openssl req -x509 -new -nodes -key "$CA_KEY" -sha256 -days 3650 -out "$CA_CERT" -config "$CA_CONFIG" -passin pass:"$CA_PASSWORD"

# Generate Server key
openssl genpkey -algorithm RSA -out "$SERVER_KEY" -pass pass:"$SERVER_PASSWORD" # -aes256
# Generate Server CSR
openssl req -new -key "$SERVER_KEY" -out "$SERVER_CSR" -config "$SERVER_CONFIG" -passin pass:"$SERVER_PASSWORD"
# Sign Server certificate with CA
openssl x509 -req -in "$SERVER_CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial -out "$SERVER_CERT" -days 365 -sha256 -extfile "$SERVER_CONFIG" -extensions v3_req -passin pass:"$CA_PASSWORD"

echo "CA and Server certificates generated successfully in $CERTS_DIR"