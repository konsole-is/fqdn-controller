package v1alpha1

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_NetworkType_ResolverString(t *testing.T) {
	tests := []struct {
		name     string
		input    NetworkType
		expected string
	}{
		{"returns ip for All", All, "ip"},
		{"returns ip4 for Ipv4", Ipv4, "ip4"},
		{"returns ip6 for Ipv6", Ipv6, "ip6"},
		{"returns empty string for unknown type", NetworkType("invalid"), ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.input.ResolverString()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func Test_NetworkPolicyResolveConditionReason_Priority(t *testing.T) {
	tests := []struct {
		name     string
		reason   NetworkPolicyResolveConditionReason
		expected int
	}{
		{"OtherError returns 6", NetworkPolicyResolveOtherError, 6},
		{"InvalidDomain returns 5", NetworkPolicyResolveInvalidDomain, 5},
		{"DomainNotFound returns 4", NetworkPolicyResolveDomainNotFound, 4},
		{"Timeout returns 3", NetworkPolicyResolveTimeout, 3},
		{"TemporaryError returns 2", NetworkPolicyResolveTemporaryError, 2},
		{"Unknown returns 1", NetworkPolicyResolveUnknown, 1},
		{"Success returns 0", NetworkPolicyResolveSuccess, 0},
		{"Unrecognized reason returns 0", NetworkPolicyResolveConditionReason("garbage"), 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := tt.reason.Priority()
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func Test_NetworkPolicyResolveConditionReason_Transient(t *testing.T) {
	tests := []struct {
		name     string
		reason   NetworkPolicyResolveConditionReason
		expected bool
	}{
		{
			name:     "InvalidDomain is not transient",
			reason:   NetworkPolicyResolveInvalidDomain,
			expected: false,
		},
		{
			name:     "DomainNotFound is not transient",
			reason:   NetworkPolicyResolveDomainNotFound,
			expected: false,
		},
		{
			name:     "Unknown reason is transient",
			reason:   "FooBar", // arbitrary string not matched by switch
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := tt.reason.Transient()
			assert.Equal(t, tt.expected, actual)
		})
	}
}
