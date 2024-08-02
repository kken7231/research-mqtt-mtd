#!/bin/bash

# Exit on any error
set -e

# Directories
CERTS_DIR="./certs"
uuid_email=false

# Parse command-line arguments
while getopts "c:u" opt; do
  case $opt in
    c) CERTS_DIR="$OPTARG" ;;
    u) uuid_email=true ;;
    \?) echo "Invalid option -$OPTARG" >&2; exit 1 ;;
  esac
done

# Directories
CLIENT_CERTS_DIR="$CERTS_DIR/clients"
mkdir -p "$CLIENT_CERTS_DIR"

# Configuration Files
if [ "$uuid_email" = true ]; then
  CLIENT_CONFIG_TEMPLATE="./conf/client_template_uuid.conf"
else
  CLIENT_CONFIG_TEMPLATE="./conf/client_template_nouuid.conf"
fi
CLIENT_CONFIG="./conf/client.conf"

# Generate sequence number
SEQ=$(ls -l $CLIENT_CERTS_DIR | grep -E 'client[0-9]+.crt' | wc -l)
SEQ=$((SEQ + 1))

# CA File Paths (Assuming CA certificate and key already exist)
CA_KEY="$CERTS_DIR/ca/ca.key"
CA_CERT="$CERTS_DIR/ca/ca.crt"
CA_PASSWORD="mqttca"

# Client File Paths
CLIENT_KEY="$CLIENT_CERTS_DIR/client$SEQ.key"
CLIENT_CSR="$CLIENT_CERTS_DIR/client$SEQ.csr"
CLIENT_CERT="$CLIENT_CERTS_DIR/client$SEQ.crt"
if [ "$uuid_email" = true ]; then
  CLIENT_UUID="$CLIENT_CERTS_DIR/client$SEQ.uuid"
fi
CLIENT_PASSWORD=""

# Generate a UUID
if [ "$uuid_email" = true ]; then
  UUID=$(uuidgen)
fi

# Create a new server configuration file with the UUID email and SEQ DNS
sed -e "s/{{SEQ}}/$SEQ/g" -e "s/{{UUID}}/$UUID/g" "$CLIENT_CONFIG_TEMPLATE" > "$CLIENT_CONFIG"

# Record UUID
if [ "$uuid_email" = true ]; then
  echo "$UUID" > "$CLIENT_UUID"
fi

# Generate Client key
openssl genpkey -algorithm RSA -out "$CLIENT_KEY" -pass pass:"$CLIENT_PASSWORD" # -aes256

# Generate Client CSR
openssl req -new -key "$CLIENT_KEY" -out "$CLIENT_CSR" -config "$CLIENT_CONFIG" -passin pass:"$CLIENT_PASSWORD"

# Sign Client certificate with CA
openssl x509 -req -in "$CLIENT_CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial -out "$CLIENT_CERT" -days 365 -sha256 -extfile "$CLIENT_CONFIG" -extensions v3_req -passin pass:"$CA_PASSWORD"

echo "Client certificate generated successfully in $CLIENT_CERTS_DIR with sequence number $SEQ"
echo "SANs: $(openssl x509 -in "$CLIENT_CERT" -noout -text | awk '/Subject Alternative Name:/ {getline; print}' | sed 's/^ *//;s/ *$//')"