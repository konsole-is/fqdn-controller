package controller

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/konsole-is/fqdn-controller/api/v1alpha1"
	"github.com/konsole-is/fqdn-controller/pkg/network"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
)

func Test_updateFQDNStatuses(t *testing.T) {
	fqdn := v1alpha1.FQDN("example.com")
	past := time.Now().Add(-5 * time.Minute)

	previous := []v1alpha1.FQDNStatus{
		{
			FQDN:               fqdn,
			LastSuccessfulTime: metav1.NewTime(past),
			LastTransitionTime: metav1.NewTime(past),
			ResolveReason:      v1alpha1.NetworkPolicyResolveSuccess,
			ResolveMessage:     "initial success",
			Addresses:          []string{"1.2.3.4/32"},
		},
	}

	// Transient error, timeout expired
	results := network.DNSResolverResultList{
		{
			Domain:  fqdn,
			Error:   fmt.Errorf("temporary error"),
			Status:  v1alpha1.NetworkPolicyResolveTemporaryError,
			Message: "failed temporarily",
			CIDRs:   []*v1alpha1.CIDR{},
		},
	}

	recorder := record.NewFakeRecorder(1)
	updated := updateFQDNStatuses(recorder, &corev1.Pod{}, previous, results, 1)

	if len(updated) != 1 {
		t.Fatalf("expected 1 status, got %d", len(updated))
	}

	status := updated[0]
	if len(status.Addresses) != 0 {
		t.Errorf("expected addresses to be cleared, got: %v", status.Addresses)
	}

	select {
	case msg := <-recorder.Events:
		if !strings.Contains(msg, "FQDNRemoved") {
			t.Errorf("expected FQDNRemoved event, got: %s", msg)
		}
	default:
		t.Error("expected an event to be emitted but got none")
	}
}
