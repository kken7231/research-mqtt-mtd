#!/bin/bash
GIT_ROOT=$(git rev-parse --show-toplevel)

# Exit on any error
set -e

# Default directories and number of certificates
CERTS_DIR="$GIT_ROOT/certs"
NUM_CERTS=5

# Parse command-line arguments
while getopts "c:n:" opt; do
  case $opt in
    c) CERTS_DIR="$OPTARG" ;;
    n) NUM_CERTS=$OPTARG ;;
    \?) echo "Invalid option -$OPTARG" >&2; exit 1 ;;
  esac
done

rm -rf "$CERTS_DIR"

# Generate CA cetrificate
./gen_ca.sh -c "$CERTS_DIR"

# Generate Client cetrificate
./gen_client.sh -c "$CERTS_DIR" -n "client" -a "$(ipconfig getifaddr en0)"

# Generate the specified number of client certificates
# for ((i = 0; i < NUM_CERTS; i++)); do
#   ./gen_client.sh -c "$CERTS_DIR"
# done