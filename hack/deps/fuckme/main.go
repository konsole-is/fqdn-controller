package main

import (
	"fmt"
	"os/exec"

	"github.com/konsole-is/fqdn-controller/test/utils"
)

func main() {
	cmd := exec.Command("kubectl", "exec", "test-curl", "-n", "default", "--",
		"curl", "-v", "-s", "-o", "/dev/null", "-w", "%{http_code}\\n",
		"--connect-timeout", fmt.Sprintf("%d", 5),
		"--max-time", fmt.Sprintf("%d", 5),
		"http://google.com",
	)
	out, err := utils.Run(cmd)
	if err != nil {
		fmt.Printf("Error running command: %v\n", err)
		return
	}
	print(out)
}
