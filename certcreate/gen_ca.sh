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

. ./gen_conf.sh

# Directories
rm -rf "$CA_CERTS_DIR"
mkdir -p "$CA_CERTS_DIR"

# Generate CA key
openssl genpkey -algorithm $CA_KEY_ALGO -out "$CA_KEY" -pkeyopt rsa_keygen_bits:$CA_KEY_LEN # -pass pass:"$CA_PASSWORD"
# Generate CA certificate
openssl req -x509 -new -nodes -key "$CA_KEY" -sha256 -days 3650 -out "$CA_CERT" -config "$CA_CONFIG" -passin pass:"$CA_PASSWORD"

echo "CA certificate generated successfully in $CERTS_DIR"