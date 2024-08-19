#!/bin/bash
GIT_ROOT=$(git rev-parse --show-toplevel)

# Exit on any error
set -e

# Directories
CERTS_DIR="$GIT_ROOT/certs"
uuid_email=false
CLIENT_NAME=""
LOCAL_IPADDR=""

# Parse command-line arguments
while getopts "c:un:a:" opt; do
  case $opt in
    c) CERTS_DIR="$OPTARG" ;;
    u) uuid_email=true ;;
    n) CLIENT_NAME="$OPTARG" ;;
    a) LOCAL_IPADDR="$OPTARG" ;;
    \?) echo "Invalid option -$OPTARG" >&2; exit 1 ;;
  esac
done

if [ "$LOCAL_IPADDR" = "" ]; then
  LOCAL_IPADDR=${CLIENT_NAME}
fi

. $GIT_ROOT/certcreate/gen_conf.sh

# Directories
mkdir -p "$CLIENT_CERTS_DIR"

# Create a new client configuration file with the UUID email and SEQ DNS
sed -e "s/{{CLIENT_NAME}}/$CLIENT_NAME/g" -e "s/{{UUID}}/$UUID/g" -e "s/{{LOCAL_IPADDR}}/$LOCAL_IPADDR/g" "$CLIENT_CONFIG_TEMPLATE" > "$CLIENT_CONFIG"

# Record UUID
if [ "$uuid_email" = true ]; then
  echo "$UUID" > "$CLIENT_UUID"
fi

# Generate Client key
openssl genpkey -algorithm $CLIENT_KEY_ALGO -out "$CLIENT_KEY" -pkeyopt rsa_keygen_bits:$CLIENT_KEY_LEN #-pass pass:"$CLIENT_PASSWORD"

# Generate Client CSR
openssl req -new -key "$CLIENT_KEY" -out "$CLIENT_CSR" -config "$CLIENT_CONFIG" -passin pass:"$CLIENT_PASSWORD"

# Sign Client certificate with CA
openssl x509 -req -in "$CLIENT_CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial -out "$CLIENT_CERT" -days 365 -extfile "$CLIENT_CONFIG" -extensions v3_req -passin pass:"$CA_PASSWORD"

echo "Client certificate generated successfully in $CLIENT_CERTS_DIR with name $CLIENT_NAME"
echo "SANs: $(openssl x509 -in "$CLIENT_CERT" -noout -text | awk '/Subject Alternative Name:/ {getline; print}' | sed 's/^ *//;s/ *$//')"