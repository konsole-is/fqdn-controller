package utils

import (
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
)

// NewCurlPod returns a long-lived curl pod definition with the given name, namespace, and labels.
// The pod sleeps indefinitely and can be exec'd into for manual curl commands.
func NewCurlPod(name, namespace string, labels map[string]string) *corev1.Pod {
	return &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Pod",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
		},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyAlways,
			Containers: []corev1.Container{
				{
					Name:    "curl",
					Image:   "curlimages/curl:latest",
					Command: []string{"sh", "-c", "sleep infinity"},
					SecurityContext: &corev1.SecurityContext{
						AllowPrivilegeEscalation: ptr.To(false),
						RunAsNonRoot:             ptr.To(true),
						RunAsUser:                ptr.To(int64(1001)),
						Capabilities: &corev1.Capabilities{
							Drop: []corev1.Capability{"ALL"},
						},
						SeccompProfile: &corev1.SeccompProfile{
							Type: corev1.SeccompProfileTypeRuntimeDefault,
						},
					},
				},
			},
		},
	}
}

// curlFromPod runs a curl command in the specified pod.
func curlFromPod(podName, namespace, url string, connectTimeout, maxTime int) (string, error) {
	cmd := exec.Command("kubectl", "exec", podName, "-n", namespace, "--",
		"curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
		"--connect-timeout", fmt.Sprintf("%d", connectTimeout),
		"--max-time", fmt.Sprintf("%d", maxTime),
		url,
	)

	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	return out.String(), err
}

// CurlSuccess returns true if the curl output indicates a successful HTTP request.
func CurlSuccess(pod types.NamespacedName, url string, timeoutSeconds int) (bool, string, error) {
	response, err := curlFromPod(pod.Name, pod.Namespace, url, timeoutSeconds, timeoutSeconds)
	statusLine := strings.TrimSpace(response)
	status, convErr := strconv.Atoi(statusLine)
	if convErr != nil {
		return false, response, fmt.Errorf("failed to parse HTTP status code from response: %q", response)
	}
	if status == 0 {
		return false, response, nil // "000" means no HTTP response
	}
	return status < 400, response, err // err may be non-nil but still OK for HTTP 301 etc.
}

// CurlFailure returns true if the curl output shows failure.
func CurlFailure(pod types.NamespacedName, url string, timeoutSeconds int) (bool, string, error) {
	success, response, err := CurlSuccess(pod, url, timeoutSeconds)

	if err != nil {
		// Treat known exit codes (like timeout) as valid failure cases
		if strings.Contains(err.Error(), "exit status 28") ||
			strings.Contains(err.Error(), "exit status 7") ||
			strings.Contains(err.Error(), "exit status 6") {
			return true, response, nil
		}
		// Any other errors are real
		return false, response, err
	}

	return !success, response, nil
}
