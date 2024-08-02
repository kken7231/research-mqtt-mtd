package common

import (
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"time"
)

func SetLen(slice *[]byte, to int) {
	if to <= cap(*slice) {
		*slice = (*slice)[:to]
	} else {
		index := 1
		mask := 0x1
		for to > mask && index < 62 {
			mask <<= 1
			mask |= 1
			index++
		}
		*slice = make([]byte, to, 1<<index)
	}
}

func ConnReadBase(conn net.Conn, dst *[]byte, timeout time.Duration) (n int, err error) {
	if timeout != 0 {
		err = conn.SetDeadline(time.Now().Add(timeout))
		if err != nil {
			return
		}
	}
	n, err = conn.Read(*dst)
	if err != nil {
		return
	}
	SetLen(dst, n)
	fmt.Printf("**(%s)> %s (%d bytes)\n", conn.RemoteAddr(), hex.EncodeToString(*dst), len(*dst))
	return
}

func ConnCancellableReadBase(conn net.Conn, dst *[]byte, timeout time.Duration, done <-chan struct{}) (n int, err error) {
	var deadline int64
	if timeout != 0 {
		deadline = time.Now().Add(timeout).UnixNano()
	} else {
		deadline = math.MaxInt64
	}
	errch := make(chan error)
	dstLen := len(*dst)
	alreadyRead := 0
	go func(done <-chan struct{}) {
		for {
			select {
			case <-done:
				return
			default:
			}
			if time.Now().UnixNano() > deadline {
				errch <- fmt.Errorf("deadline reached")
				return
			}

			conn.SetReadDeadline(time.Now().Add(time.Second))
			if n, err := conn.Read((*dst)[alreadyRead:]); err == nil {
				alreadyRead += n
				fmt.Printf("c*(%s)> %s (%d bytes)\n", conn.RemoteAddr(), hex.EncodeToString(*dst), len(*dst))
				if alreadyRead == dstLen {
					errch <- nil
					return
				}
			} else if alreadyRead > 0 && n == 0 {
				SetLen(dst, alreadyRead)
				errch <- nil
				return
			} else if nerr, ok := err.(net.Error); !ok || !nerr.Timeout() {
				errch <- err
				return
			}
		}
	}(done)

	select {
	case err = <-errch:
		return
	case <-done:
		err = fmt.Errorf("interrupted by chan")
		return
	}
}

func ConnWriteBase(conn net.Conn, data []byte, timeout time.Duration) (n int, err error) {
	if timeout != 0 {
		err = conn.SetDeadline(time.Now().Add(timeout))
		if err != nil {
			return
		}
	}
	n, err = conn.Write(data)
	if err != nil {
		return
	}
	fmt.Printf("**>(%s) %s (%d bytes)\n", conn.RemoteAddr(), hex.EncodeToString(data), len(data))
	return
}

func ConnCancellableWriteBase(conn net.Conn, data []byte, timeout time.Duration, done <-chan struct{}) (n int, err error) {
	var deadline int64
	if timeout != 0 {
		deadline = time.Now().Add(timeout).UnixNano()
	} else {
		deadline = math.MaxInt64
	}
	errch := make(chan error)
	dataLen := len(data)
	alreadyWrote := 0
	loopAllowed := true
	go func() {
		var n int
		for loopAllowed {
			if time.Now().UnixNano() > deadline {
				errch <- fmt.Errorf("deadline reached")
				return
			}

			conn.SetWriteDeadline(time.Now().Add(time.Second))
			if n, err = conn.Write(data[alreadyWrote : alreadyWrote+int(math.Min(256, float64(dataLen-alreadyWrote)))]); err == nil {
				fmt.Printf("c*>(%s) %s (%d bytes)\n", conn.RemoteAddr(), hex.EncodeToString(data[alreadyWrote:alreadyWrote+n]), n)
				alreadyWrote += n
				if alreadyWrote == dataLen {
					errch <- nil
					return
				}
			} else if err != io.EOF {
				errch <- err
				return
			}
		}
	}()

	select {
	case err = <-errch:
		return
	case <-done:
		loopAllowed = false
		return
	}
}

func PopRandomBytesFromFileBase(tokenFilePath string, timestampLen int, randomBytesLen int, fileStartsWithTimestamp bool) (timestamp []byte, randomBytes []byte, err error) {
	if _, err = os.Stat(tokenFilePath); err == nil {
		var (
			isAlreadyClosed bool = false
			tokenFile       *os.File
		)
		tokenFile, err = os.Open(tokenFilePath)
		if err != nil {
			err = fmt.Errorf("failed opening file to pop a token: %v", err)
			return
		}
		defer func() {
			if !isAlreadyClosed {
				tokenFile.Close()
			}
		}()

		if fileStartsWithTimestamp {
			timestamp = make([]byte, timestampLen)
			if _, err = tokenFile.Read(timestamp); err != nil {
				err = fmt.Errorf("failed getting the timestamp to pop a token: %v", err)
				return
			}
		}

		randomBytes = make([]byte, randomBytesLen)
		if _, err = tokenFile.Read(randomBytes); err != nil {
			err = fmt.Errorf("failed getting the next token to pop a token: %v", err)
			return
		}

		buf := make([]byte, randomBytesLen)
		if _, err = tokenFile.Read(buf); err != nil {
			// Remove file
			if err == io.EOF {
				err = nil
				fmt.Printf("Removing file %s since only one token left\n", tokenFilePath)
			} else {
				err = fmt.Errorf("found error when reading tokenFile: %v", err)
			}
			tokenFile.Close()
			if oserr := os.Remove(tokenFilePath); oserr != nil {
				err = fmt.Errorf("failed removing file %s: %v with preceding error? %v", tokenFilePath, oserr, err)
				return
			} else if err != nil {
				return
			}
			isAlreadyClosed = true
		} else {
			tokenFilePathTmp := tokenFilePath + ".tmp"
			created := false
			err = func() error {
				tokenFileTmp, err := os.Create(tokenFilePathTmp)
				if _, err := tokenFileTmp.Write(timestamp); err != nil {
					err = fmt.Errorf("failed writing timestamp into tmp file %s: %v", tokenFilePathTmp, err)
					tokenFileTmp.Close()
					if oserr := os.Remove(tokenFilePathTmp); err != nil {
						err = fmt.Errorf("failed removing tmp file %s: %v with preceding error %v", tokenFilePath, oserr, err)
					}
					return err
				}

				for err == nil {
					if _, err := tokenFileTmp.Write(buf); err != nil {
						err = fmt.Errorf("failed writing random bytes into tmp file %s: %v", tokenFilePathTmp, err)
						tokenFileTmp.Close()
						if oserr := os.Remove(tokenFilePathTmp); oserr != nil {
							err = fmt.Errorf("failed removing tmp file %s: %v with preceding error %v", tokenFilePath, oserr, err)
						}
						return err
					}
					_, err = tokenFile.Read(buf)
				}
				tokenFileTmp.Close()
				created = true
				return nil
			}()
			tokenFile.Close()
			isAlreadyClosed = true
			if created {
				if oserr := os.Rename(tokenFilePathTmp, tokenFilePath); oserr != nil {
					err = fmt.Errorf("failed replacing file %s: %v", tokenFilePath, oserr)
					return
				}
			} else {
				if oserr := os.Remove(tokenFilePath); oserr != nil {
					err = fmt.Errorf("failed removing file %s: %v with preceding error %v", tokenFilePath, oserr, err)
				}
				return
			}
		}
		return
	} else {
		err = nil
	}
	return
}
