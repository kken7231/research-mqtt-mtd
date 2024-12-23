package funcs

import (
	"context"
	"encoding/hex"
	"fmt"
	"mqttmtd/consts"
	"net"
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

func NewCancelableContext(isCancelable bool) (ctx context.Context, cancel context.CancelFunc) {
	ctx, cancel = context.WithCancel(context.Background())
	ctx = context.WithValue(ctx, consts.SOCK_CONTEXT_CANCELABLE_KEY, isCancelable)
	return
}
func ConnRead(ctx context.Context, conn net.Conn, dst []byte, timeout time.Duration) (n int, err error) {
	if v := ctx.Value(consts.SOCK_CONTEXT_CANCELABLE_KEY); v != nil {
		if cancelable, ok := v.(bool); ok && cancelable {
			return connReadCancelable(ctx, conn, dst, timeout)
		}
	}
	return connReadNonCancelable(conn, dst, timeout)
}

func connReadNonCancelable(conn net.Conn, dst []byte, timeout time.Duration) (n int, err error) {
	total := 0
	for total < len(dst) {
		if timeout != 0 {
			err = conn.SetReadDeadline(time.Now().Add(timeout))
			if err != nil {
				return total, err
			}
		}

		n, err := conn.Read(dst[total:])
		if err != nil {
			return total, err
		}
		fmt.Printf("**(%s)> %s (%d bytes)\n", conn.RemoteAddr(), hex.EncodeToString(dst[total:total+n]), n)
		total += n
	}
	return total, nil
}

func connReadCancelable(ctx context.Context, conn net.Conn, dst []byte, timeout time.Duration) (n int, err error) {
	total := 0
	result := make(chan struct {
		n   int
		err error
	})

	for total < len(dst) {
		go func() {
			if timeout != 0 {
				err := conn.SetReadDeadline(time.Now().Add(timeout))
				if err != nil {
					result <- struct {
						n   int
						err error
					}{0, err}
					return
				}
			}

			n, err := conn.Read(dst[total:])
			if err != nil {
				result <- struct {
					n   int
					err error
				}{n, err}
			} else {
				result <- struct {
					n   int
					err error
				}{n, nil}
			}
		}()

		select {
		case <-ctx.Done():
			fmt.Println("read interrupted by ctx.cancel")
			return total, ctx.Err()
		case res := <-result:
			if res.err != nil {
				return total, res.err
			}
			total += res.n
			fmt.Printf("**(%s)> %s (%d bytes)\n", conn.RemoteAddr(), hex.EncodeToString(dst[:total]), total)
		}
	}

	return total, nil
}

func ConnWrite(ctx context.Context, conn net.Conn, data []byte, timeout time.Duration) (n int, err error) {
	if ctx == nil {
		return connWriteNonCancelable(conn, data, timeout)
	} else {
		return connWriteCancelable(ctx, conn, data, timeout)
	}
}

func connWriteNonCancelable(conn net.Conn, data []byte, timeout time.Duration) (n int, err error) {
	if timeout != 0 {
		err = conn.SetWriteDeadline(time.Now().Add(timeout))
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

func connWriteCancelable(ctx context.Context, conn net.Conn, data []byte, timeout time.Duration) (n int, err error) {
	result := make(chan struct {
		n   int
		err error
	})

	go func() {
		var err error
		if timeout != 0 {
			err = conn.SetWriteDeadline(time.Now().Add(timeout))
			if err != nil {
				result <- struct {
					n   int
					err error
				}{0, err}
			}
		}
		n, err := conn.Write(data)
		fmt.Printf("**>(%s) %s (%d bytes)\n", conn.RemoteAddr(), hex.EncodeToString(data), len(data))
		result <- struct {
			n   int
			err error
		}{n, err}
	}()

	select {
	case <-ctx.Done():
		fmt.Println("write interrupted by ctx.cancel")
		return 0, ctx.Err()
	case res := <-result:
		return res.n, res.err
	}
}
