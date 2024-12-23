package main

import (
	"flag"
	"log"
	"mqttmtd/authserver/autorevoker"
	"mqttmtd/authserver/dashboardserver"
	"mqttmtd/authserver/issuer"
	"mqttmtd/authserver/verifier"
	"mqttmtd/config"
	"mqttmtd/types"
)

var (
	acl = &types.AccessControlList{}
	atl = &types.AuthTokenList{}
)

func main() {

	configFilePath := flag.String("conf", "", "path to the server conf file")
	flag.Parse()

	if err := config.LoadServerConfig(*configFilePath); err != nil {
		log.Fatalf("Failed to load server config from %s: %v", *configFilePath, err)
	} else {
		log.Printf("Server Config Loaded from %s\n", *configFilePath)
	}

	if err := acl.LoadFile(config.Server.FilePaths.AclFilePath); err != nil {
		log.Fatalf("Failed to load ACL: %v", err)
	}

	go issuer.Run(acl, atl)
	go verifier.Run(atl)
	go autorevoker.Run(atl)
	go dashboardserver.Run(acl, atl)

	select {}
}
