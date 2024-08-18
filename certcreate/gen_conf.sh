#!/bin/bash
CERTCREATE_DIR="$(git rev-parse --show-toplevel)/certcreate"

# Directories
export CA_CERTS_DIR="$CERTS_DIR/ca"
export SERVER_CERTS_DIR="$CERTS_DIR/server"
export CLIENT_CERTS_DIR="$CERTS_DIR/clients"

# Configuration Files
export CA_CONFIG="$CERTCREATE_DIR/conf/ca.conf"
export SERVER_CONFIG_TEMPLATE="$CERTCREATE_DIR/conf/server_template.conf"
export SERVER_CONFIG="$CERTCREATE_DIR/conf/server.conf"
if [ "$uuid_email" = true ]; then
  export CLIENT_CONFIG_TEMPLATE="$CERTCREATE_DIR/conf/client_template_uuid.conf"
else
  export CLIENT_CONFIG_TEMPLATE="$CERTCREATE_DIR/conf/client_template_nouuid.conf"
fi
export CLIENT_CONFIG="$CERTCREATE_DIR/conf/client.conf"

# CA File Paths
export CA_KEY="$CA_CERTS_DIR/ca.key"
export CA_KEY_ALGO=RSA
export CA_KEY_LEN=3072
export CA_CERT="$CA_CERTS_DIR/ca.pem"
export CA_PASSWORD="mqttca"

# Server File Paths
export SERVER_KEY="$SERVER_CERTS_DIR/server.key"
export SERVER_KEY_ALGO=RSA
export SERVER_KEY_LEN=3072
export SERVER_CSR="$SERVER_CERTS_DIR/server.csr"
export SERVER_CERT="$SERVER_CERTS_DIR/server.pem"
# export SERVER_DH="$SERVER_CERTS_DIR/dhparam.pem"
export SERVER_PASSWORD=""


# Client File Paths
if [ "$CLIENT_NAME" = "" ]; then
  # Client sequence number
  SEQ=$(ls -l $CLIENT_CERTS_DIR | grep -E 'client[0-9]+.pem' | wc -l)
  SEQ=$((SEQ + 1))
  CLIENT_NAME="client$SEQ"
fi
export CLIENT_KEY="$CLIENT_CERTS_DIR/$CLIENT_NAME.key"
export CLIENT_KEY_ALGO=RSA
export CLIENT_KEY_LEN=3072
export CLIENT_CSR="$CLIENT_CERTS_DIR/$CLIENT_NAME.csr"
export CLIENT_CERT="$CLIENT_CERTS_DIR/$CLIENT_NAME.pem"
if [ "$uuid_email" = true ]; then
  export CLIENT_UUID="$CLIENT_CERTS_DIR/$CLIENT_NAME.uuid"
  export UUID=$(uuidgen)
fi
export CLIENT_PASSWORD=""
