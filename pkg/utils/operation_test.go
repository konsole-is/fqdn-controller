package utils

import (
	"github.com/konsole-is/fqdn-controller/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"testing"
)

var object = &v1alpha1.NetworkPolicy{}

func Test_OperationErrorReason(t *testing.T) {
	reason := OperationErrorReason(object)
	assert.Equal(t, "NetworkPolicyError", reason)
}

func Test_OperationReason(t *testing.T) {
	tests := []struct {
		name     string
		op       controllerutil.OperationResult
		expected string
	}{
		{"created", controllerutil.OperationResultCreated, "NetworkPolicyCreated"},
		{"updated", controllerutil.OperationResultUpdated, "NetworkPolicyUpdated"},
		{"status updated", controllerutil.OperationResultUpdatedStatus, "NetworkPolicyStatusUpdated"},
		{"status updated only", controllerutil.OperationResultUpdatedStatusOnly, "NetworkPolicyStatusUpdated"},
		{"unchanged", controllerutil.OperationResultNone, "NetworkPolicyUnchanged"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason := OperationReason(object, tt.op)
			assert.Equal(t, tt.expected, reason)
		})
	}
}

func Test_OperationMessage(t *testing.T) {
	tests := []struct {
		name     string
		op       controllerutil.OperationResult
		expected string
	}{
		{"created", controllerutil.OperationResultCreated, "NetworkPolicy was created"},
		{"updated", controllerutil.OperationResultUpdated, "NetworkPolicy was updated"},
		{"status updated", controllerutil.OperationResultUpdatedStatus, "NetworkPolicy had it's status updated"},
		{"status updated only", controllerutil.OperationResultUpdatedStatusOnly, "NetworkPolicy had it's status updated"},
		{"unchanged", controllerutil.OperationResultNone, "NetworkPolicy is unchanged"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := OperationMessage(object, tt.op)
			assert.Equal(t, tt.expected, msg)
		})
	}
}
