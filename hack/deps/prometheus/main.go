package main

import (
	"github.com/konsole-is/fqdn-controller/test/utils"
	"log"
)

func main() {
	if err := utils.InstallPrometheusOperator(); err != nil {
		log.Fatalf("failed to install prometheus-operator: %v", err)
	}
}
