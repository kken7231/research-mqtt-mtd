package consts

import (
	"time"
)

const (
	DEFAULT_FILEPATH_ACL        = "/mqttmtd/acl.yml"
	DEFAULT_FILEPATH_TOKENS_DIR = "/mqttmtd/tokens/"

	CA_CRTFILE = "/mqttmtd/certs/ca/ca.crt"
	CA_KEYFILE = "/mqttmtd/certs/ca/ca.key"

	SERVER_CRTFILE = "/mqttmtd/certs/server/server.crt"
	SERVER_KEYFILE = "/mqttmtd/certs/server/server.key"

	LADDR_ISSUER     = ":18883"
	LADDR_VERIFIER   = ":21883"
	LADDR_HTTPSERVER = ":8080"

	DEFAULT_NUM_TOKENS = 5

	TIMESTAMP_LEN    = 6
	RANDOM_BYTES_LEN = 6
	TOKEN_SIZE       = TIMESTAMP_LEN + RANDOM_BYTES_LEN

	TIME_REVOCATION = time.Hour * 24 * 7
)
