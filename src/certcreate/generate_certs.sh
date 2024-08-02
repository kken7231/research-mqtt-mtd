#!/bin/bash

# Exit on any error
set -e

# Default directories and number of certificates
CERTS_DIR="./certs"
NUM_CERTS=5

# Parse command-line arguments
while getopts "c:n:" opt; do
  case $opt in
    c) CERTS_DIR="$OPTARG" ;;
    n) NUM_CERTS=$OPTARG ;;
    \?) echo "Invalid option -$OPTARG" >&2; exit 1 ;;
  esac
done

# Generate CA and Server certificates
./gen_ca_server.sh -c "$CERTS_DIR"

# Generate the specified number of client certificates
for ((i = 0; i < NUM_CERTS; i++)); do
  ./gen_client.sh -c "$CERTS_DIR"
done