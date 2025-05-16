package autorevoker

import (
	"fmt"
	"mqttmtd/types"
	"time"
)

func Run(atl *types.AuthTokenList) {
	fmt.Println("AutoRevoker started")
	for {
		time.Sleep(time.Minute)
		atl.Lock()
		atl.RemoveExpired()
		atl.Unlock()
		fmt.Printf("%s: AutoRevoker removed expired tokens\n", time.Now().Local().Format(time.StampMilli))
	}
}
