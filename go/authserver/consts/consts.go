package consts

import (
	"time"
)

const (
	MQTTENV_DIR = "/Users/kentarito/git/research-mqtt-mtd/.mqttenv"
	// MQTTENV_DIR = "/Users/kentarou/git/research-mqtt-mtd/.mqttenv"
	// MQTTENV_DIR = "/" if linux/docker

	DEFAULT_FILEPATH_ACL        = MQTTENV_DIR + "/mqttmtd/config/acl.yml"
	DEFAULT_FILEPATH_TOKENS_DIR = MQTTENV_DIR + "/mqttmtd/tokens/"

	CA_CRTFILE = MQTTENV_DIR + "/mqttmtd/certs/ca/ca.pem"
	CA_KEYFILE = MQTTENV_DIR + "/mqttmtd/certs/ca/ca.key"

	SERVER_CRTFILE = MQTTENV_DIR + "/mqttmtd/certs/server/server.pem"
	SERVER_KEYFILE = MQTTENV_DIR + "/mqttmtd/certs/server/server.key"

	LADDR_ISSUER     = ":18883"
	LADDR_VERIFIER   = ":21883"
	LADDR_HTTPSERVER = ":8080"

	DEFAULT_NUM_TOKENS = 5

	TIMESTAMP_LEN    = 6
	RANDOM_BYTES_LEN = 6
	TOKEN_SIZE       = TIMESTAMP_LEN + RANDOM_BYTES_LEN

	TIME_REVOCATION = time.Hour * 24 * 7
)
