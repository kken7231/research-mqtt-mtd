package main

import (
	"flag"
	"go/authserver/autorevoker"
	"go/authserver/consts"
	"go/authserver/dashboardserver"
	"go/authserver/issuer"
	"go/authserver/types"
	"go/authserver/verifier"
	"log"
)

var (
	acl = &types.AccessControlList{}
	atl = &types.AuthTokenList{}
)

func main() {
	aclFilePath := flag.String("acl", consts.DEFAULT_FILEPATH_ACL, "path to the ACL file")
	flag.Parse()

	err := acl.LoadFile(*aclFilePath)
	if err != nil {
		log.Fatalf("Failed to load ACL: %v", err)
	}

	go issuer.Run(acl, atl)
	go verifier.Run(atl)
	go autorevoker.Run(atl)
	go dashboardserver.Run(acl, atl)

	select {}
}
