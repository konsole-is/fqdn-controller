package main

import (
	"log"

	"github.com/konsole-is/fqdn-controller/test/utils"
)

func main() {
	if err := utils.InstallPrometheusOperator(); err != nil {
		log.Fatalf("failed to install prometheus-operator: %v", err)
	}
}
