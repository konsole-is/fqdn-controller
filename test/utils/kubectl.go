package utils

import (
	"bytes"
	"fmt"
	"os/exec"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"
)

func KubectlApply(object client.Object) error {
	objYaml, err := yaml.Marshal(object)
	if err != nil {
		return err
	}

	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = bytes.NewReader(objYaml)
	_, err = Run(cmd)
	return err
}

func KubectlDelete(object client.Object) error {
	objYaml, err := yaml.Marshal(object)
	if err != nil {
		return err
	}

	cmd := exec.Command("kubectl", "delete", "-f", "-")
	cmd.Stdin = bytes.NewReader(objYaml)
	_, err = Run(cmd)
	return err
}

func KubectlGetJSONPath(obj client.Object, kind string, jsonPath string) (string, error) {
	cmd := exec.Command(
		"kubectl", "get", kind, obj.GetName(),
		"-n", obj.GetNamespace(),
		"-o", fmt.Sprintf("jsonpath={%s}", jsonPath),
	)

	output, err := Run(cmd)
	if err != nil {
		return "", err
	}
	return output, nil
}
