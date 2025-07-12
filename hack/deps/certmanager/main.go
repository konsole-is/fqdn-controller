package main

import (
	"log"

	"github.com/konsole-is/fqdn-controller/test/utils"
)

func main() {
	if err := utils.InstallCertManager(); err != nil {
		log.Fatalf("failed to install cert-manager: %v", err)
	}
}
