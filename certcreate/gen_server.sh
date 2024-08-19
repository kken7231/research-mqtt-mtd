#!/bin/bash
GIT_ROOT=$(git rev-parse --show-toplevel)

# Exit on any error
set -e

# Directories
CERTS_DIR="./certs"
LOCAL_IPADDR="server"

# Parse command-line arguments
while getopts "c:a:" opt; do
  case $opt in
    c) CERTS_DIR="$OPTARG" ;;
    a) LOCAL_IPADDR="$OPTARG" ;;
    \?) echo "Invalid option -$OPTARG" >&2; exit 1 ;;
  esac
done

. $GIT_ROOT/certcreate/gen_conf.sh

# Directories
rm -rf "$SERVER_CERTS_DIR"
mkdir -p "$SERVER_CERTS_DIR"

# Create a new server configuration file with the UUID email and SEQ DNS
sed -e "s/{{LOCAL_IPADDR}}/$LOCAL_IPADDR/g" "$SERVER_CONFIG_TEMPLATE" > "$SERVER_CONFIG"

# Generate Server key
openssl genpkey -algorithm $SERVER_KEY_ALGO -out "$SERVER_KEY" -pkeyopt rsa_keygen_bits:$SERVER_KEY_LEN #-pass pass:"$SERVER_PASSWORD"
# Generate Server CSR
openssl req -new -key "$SERVER_KEY" -out "$SERVER_CSR" -config "$SERVER_CONFIG" -passin pass:"$SERVER_PASSWORD"
# Sign Server certificate with CA
openssl x509 -req -in "$SERVER_CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial -out "$SERVER_CERT" -days 365 -extfile "$SERVER_CONFIG" -extensions v3_req -passin pass:"$CA_PASSWORD"

echo "Server certificate generated successfully in $CERTS_DIR with CN=$LOCAL_IPADDR"