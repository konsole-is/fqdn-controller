package utils

import (
	"github.com/stretchr/testify/assert"
	netv1 "k8s.io/api/networking/v1"
	"testing"
)

func Test_UniqueCidrsInNetworkPolicy(t *testing.T) {
	tests := []struct {
		name     string
		policy   *netv1.NetworkPolicy
		expected []string // expected CIDR strings
	}{
		{
			name:     "nil network policy",
			policy:   nil,
			expected: []string{},
		},
		{
			name: "ingress and egress with unique CIDRs",
			policy: &netv1.NetworkPolicy{
				Spec: netv1.NetworkPolicySpec{
					Ingress: []netv1.NetworkPolicyIngressRule{
						{
							From: []netv1.NetworkPolicyPeer{
								{IPBlock: &netv1.IPBlock{CIDR: "1.1.1.1/32"}},
								{IPBlock: &netv1.IPBlock{CIDR: "2.2.2.2/32"}},
							},
						},
					},
					Egress: []netv1.NetworkPolicyEgressRule{
						{
							To: []netv1.NetworkPolicyPeer{
								{IPBlock: &netv1.IPBlock{CIDR: "3.3.3.3/32"}},
							},
						},
					},
				},
			},
			expected: []string{"1.1.1.1/32", "2.2.2.2/32", "3.3.3.3/32"},
		},
		{
			name: "duplicate CIDRs in ingress and egress",
			policy: &netv1.NetworkPolicy{
				Spec: netv1.NetworkPolicySpec{
					Ingress: []netv1.NetworkPolicyIngressRule{
						{From: []netv1.NetworkPolicyPeer{
							{IPBlock: &netv1.IPBlock{CIDR: "4.4.4.4/32"}},
						}},
					},
					Egress: []netv1.NetworkPolicyEgressRule{
						{To: []netv1.NetworkPolicyPeer{
							{IPBlock: &netv1.IPBlock{CIDR: "4.4.4.4/32"}},
						}},
					},
				},
			},
			expected: []string{"4.4.4.4/32"},
		},
		{
			name: "include 0.0.0.0/0 CIDR",
			policy: &netv1.NetworkPolicy{
				Spec: netv1.NetworkPolicySpec{
					Ingress: []netv1.NetworkPolicyIngressRule{
						{From: []netv1.NetworkPolicyPeer{
							{IPBlock: &netv1.IPBlock{CIDR: "0.0.0.0/0"}},
							{IPBlock: &netv1.IPBlock{CIDR: "10.0.0.0/8"}},
						}},
					},
				},
			},
			expected: []string{"0.0.0.0/0", "10.0.0.0/8"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cidrs := UniqueCidrsInNetworkPolicy(tt.policy)
			var result []string
			for _, c := range cidrs {
				result = append(result, c.String())
			}
			assert.ElementsMatch(t, tt.expected, result)
		})
	}
}
