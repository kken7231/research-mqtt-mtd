package funcs

import (
	"encoding/base64"
	"go/authserver/consts"
	"go/common"
	"net"
	"time"
)

func ConnRead(conn net.Conn, dst *[]byte, timeout time.Duration) (n int, err error) {
	return common.ConnReadBase(conn, dst, timeout)
}

func ConnWrite(conn net.Conn, data []byte, timeout time.Duration) (n int, err error) {
	return common.ConnWriteBase(conn, data, timeout)
}

func PopRandomBytesFromFile(timestamp [1 + consts.TIMESTAMP_LEN]byte) (randomBytes []byte, err error) {
	tokenFilePath := consts.DEFAULT_FILEPATH_TOKENS_DIR + base64.RawURLEncoding.EncodeToString(timestamp[:])
	_, _, _, randomBytes, err = common.PopRandomBytesFromFileBase(tokenFilePath, consts.TIMESTAMP_LEN, consts.RANDOM_BYTES_LEN, false, false)
	return
}
