package v1alpha1

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func Test_NewCIDR_ValidIPv4(t *testing.T) {
	cidr, err := NewCIDR("192.168.1.1/24")
	require.NoError(t, err)
	assert.NotNil(t, cidr)
	assert.Equal(t, net.ParseIP("192.168.1.1"), cidr.IP)
	assert.Equal(t, 24, cidr.Prefix)
}

func Test_NewCIDR_ValidIPv6(t *testing.T) {
	cidr, err := NewCIDR("2001:db8::1/64")
	require.NoError(t, err)
	assert.NotNil(t, cidr)
	assert.Equal(t, net.ParseIP("2001:db8::1"), cidr.IP)
	assert.Equal(t, 64, cidr.Prefix)
}

func Test_NewCIDR_InvalidCIDRFormat(t *testing.T) {
	cidr, err := NewCIDR("192.168.1.1") // missing prefix
	require.Error(t, err)
	assert.Nil(t, cidr)
}

func Test_NewCIDR_EmptyString(t *testing.T) {
	cidr, err := NewCIDR("")
	require.Error(t, err)
	assert.Nil(t, cidr)
}

func Test_NewCIDR_InvalidPrefix(t *testing.T) {
	cidr, err := NewCIDR("192.168.1.1/abc")
	require.Error(t, err)
	assert.Nil(t, cidr)
}

func Test_CIDR_String(t *testing.T) {
	tests := []struct {
		name     string
		cidr     *CIDR
		expected string
	}{
		{
			name:     "IPv4",
			cidr:     &CIDR{IP: net.ParseIP("192.168.1.1"), Prefix: 24},
			expected: "192.168.1.1/24",
		},
		{
			name:     "IPv6",
			cidr:     &CIDR{IP: net.ParseIP("2001:db8::1"), Prefix: 64},
			expected: "2001:db8::1/64",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.cidr.String())
		})
	}
}

func Test_CIDR_IsPrivate(t *testing.T) {
	tests := []struct {
		name     string
		cidr     *CIDR
		expected bool
	}{
		{
			name:     "Private IPv4 (192.168)",
			cidr:     &CIDR{IP: net.ParseIP("192.168.0.1"), Prefix: 24},
			expected: true,
		},
		{
			name:     "Private IPv4 (10.0.0.0)",
			cidr:     &CIDR{IP: net.ParseIP("10.1.1.1"), Prefix: 16},
			expected: true,
		},
		{
			name:     "Public IPv4",
			cidr:     &CIDR{IP: net.ParseIP("8.8.8.8"), Prefix: 32},
			expected: false,
		},
		{
			name:     "Public IPv6",
			cidr:     &CIDR{IP: net.ParseIP("2001:4860:4860::8888"), Prefix: 128},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.cidr.IsPrivate())
		})
	}
}

func Test_CIDRList_String(t *testing.T) {
	list := CIDRList{
		&CIDR{IP: net.ParseIP("192.168.1.1"), Prefix: 24},
		&CIDR{IP: net.ParseIP("10.0.0.1"), Prefix: 16},
		&CIDR{IP: net.ParseIP("2001:db8::1"), Prefix: 64},
	}

	expected := []string{
		"192.168.1.1/24",
		"10.0.0.1/16",
		"2001:db8::1/64",
	}

	assert.Equal(t, expected, list.String())
}

func Test_FQDN_Valid(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"example.com", true},
		{"foo.example.com", true},
		{"a-b-c.example.io", true},
		{"abc123.example", true},
		{"abc.-example.com", false},               // label starts with hyphen
		{"-abc.example.com", false},               // label starts with hyphen
		{"abc..example.com", false},               // empty label
		{"abc.example..com", false},               // empty label
		{"abc.example", true},                     // still 2+ labels
		{"localhost", false},                      // only one label
		{"", false},                               // empty string
		{".", false},                              // root dot
		{"a..b.com", false},                       // double dots
		{"a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p", true}, // many labels
		{"123", false},                            // single numeric label
		{"abc.example.123", true},                 // numeric TLD allowed syntactically
		{"abc.123", true},
		{"abc.#$.com", false}, // invalid characters
		{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com", true},   // 63-char label
		{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com", false}, // 64-char label
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			fqdn := FQDN(tt.input)
			assert.Equal(t, tt.expected, fqdn.Valid())
		})
	}
}

func Test_isAllowed(t *testing.T) {
	trueVal := true
	falseVal := false

	tests := []struct {
		name               string
		globalBlockPrivate bool
		ruleBlockPrivate   *bool
		cidr               string
		isAllowed          bool
	}{
		{
			name:               "global true, rule nil (private IP)",
			globalBlockPrivate: true,
			ruleBlockPrivate:   nil,
			cidr:               "192.168.1.1/32",
			isAllowed:          false,
		},
		{
			name:               "global false, rule nil (private IP)",
			globalBlockPrivate: false,
			ruleBlockPrivate:   nil,
			cidr:               "192.168.1.1/32",
			isAllowed:          true,
		},
		{
			name:               "global true, rule false (private IP)",
			globalBlockPrivate: true,
			ruleBlockPrivate:   &falseVal,
			cidr:               "192.168.1.1/32",
			isAllowed:          true,
		},
		{
			name:               "global false, rule true (private IP)",
			globalBlockPrivate: false,
			ruleBlockPrivate:   &trueVal,
			cidr:               "192.168.1.1/32",
			isAllowed:          false,
		},
		{
			name:               "public IP always allowed",
			globalBlockPrivate: true,
			ruleBlockPrivate:   nil,
			cidr:               "8.8.8.8/32",
			isAllowed:          true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := isAllowed(tt.cidr, tt.globalBlockPrivate, tt.ruleBlockPrivate)
			assert.Equal(t, tt.isAllowed, actual)
		})
	}
}

func Test_getPeers(t *testing.T) {
	trueVal := true
	falseVal := false

	tests := []struct {
		name        string
		fqdns       []FQDN
		ips         map[FQDN]*FQDNStatus
		globalBlock bool
		ruleBlock   *bool
		expected    []string
	}{
		{
			name:        "include private and public",
			fqdns:       []FQDN{"example.com"},
			globalBlock: false,
			ruleBlock:   nil,
			ips: map[FQDN]*FQDNStatus{
				"example.com": {
					Addresses: []string{
						MustCIDR("192.168.1.1/32").String(),
						MustCIDR("8.8.8.8/32").String(),
					},
				},
			},
			expected: []string{"192.168.1.1/32", "8.8.8.8/32"},
		},
		{
			name:        "exclude private",
			fqdns:       []FQDN{"example.com"},
			globalBlock: true,
			ruleBlock:   nil,
			ips: map[FQDN]*FQDNStatus{
				"example.com": {
					Addresses: []string{
						MustCIDR("192.168.1.1/32").String(),
						MustCIDR("8.8.8.8/32").String(),
					},
				},
			},
			expected: []string{"8.8.8.8/32"},
		},
		{
			name:        "no matching FQDN",
			fqdns:       []FQDN{"missing.com"},
			globalBlock: true,
			ruleBlock:   nil,
			ips: map[FQDN]*FQDNStatus{
				"example.com": {
					Addresses: []string{MustCIDR("1.1.1.1/32").String()},
				},
			},
			expected: []string{},
		},
		{
			name:        "multiple FQDNs with mixed IPs",
			fqdns:       []FQDN{"example.com", "google.com"},
			globalBlock: true,
			ruleBlock:   nil,
			ips: map[FQDN]*FQDNStatus{
				"example.com": {
					Addresses: []string{MustCIDR("8.8.8.8/32").String()},
				},
				"google.com": {
					Addresses: []string{
						MustCIDR("10.0.0.1/32").String(),
						MustCIDR("1.1.1.1/32").String(),
					},
				},
			},
			expected: []string{"8.8.8.8/32", "1.1.1.1/32"},
		},
		{
			name:        "rule override: allow private despite global block",
			fqdns:       []FQDN{"example.com"},
			globalBlock: true,
			ruleBlock:   &falseVal,
			ips: map[FQDN]*FQDNStatus{
				"example.com": {
					Addresses: []string{
						MustCIDR("192.168.1.1/32").String(),
						MustCIDR("8.8.8.8/32").String(),
					},
				},
			},
			expected: []string{"192.168.1.1/32", "8.8.8.8/32"},
		},
		{
			name:        "rule override: block private even if global allows",
			fqdns:       []FQDN{"example.com"},
			globalBlock: false,
			ruleBlock:   &trueVal,
			ips: map[FQDN]*FQDNStatus{
				"example.com": {
					Addresses: []string{
						"10.0.0.1/32",
						"1.1.1.1/32",
					},
				},
			},
			expected: []string{"1.1.1.1/32"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peers := getPeers(tt.fqdns, tt.ips, tt.globalBlock, tt.ruleBlock)

			var got []string
			for _, peer := range peers {
				got = append(got, peer.IPBlock.CIDR)
			}
			assert.ElementsMatch(t, tt.expected, got)
		})
	}
}

func intStrPtr(i int) *intstr.IntOrString {
	v := intstr.FromInt32(int32(i))
	return &v
}

func boolPtr(b bool) *bool {
	return &b
}

func Test_EgressRule_toNetworkPolicyEgressRule(t *testing.T) {
	tests := []struct {
		name         string
		rule         EgressRule
		ipMap        map[FQDN]*FQDNStatus
		blockPrivate bool
		expectNil    bool
		expectCIDRs  []string
	}{
		{
			name: "no matching FQDNs, returns nil",
			rule: EgressRule{
				ToFQDNS: []FQDN{"missing.com"},
			},
			ipMap:        map[FQDN]*FQDNStatus{},
			blockPrivate: false,
			expectNil:    true,
		},
		{
			name: "one public CIDR allowed",
			rule: EgressRule{
				ToFQDNS: []FQDN{"public.com"},
			},
			ipMap: map[FQDN]*FQDNStatus{
				"public.com": {
					Addresses: []string{MustCIDR("8.8.8.8/32").String()},
				},
			},
			blockPrivate: false,
			expectCIDRs:  []string{"8.8.8.8/32"},
		},
		{
			name: "private CIDR excluded by default",
			rule: EgressRule{
				ToFQDNS: []FQDN{"private.com"},
			},
			ipMap: map[FQDN]*FQDNStatus{
				"private.com": {
					Addresses: []string{MustCIDR("192.168.0.1/32").String()},
				},
			},
			blockPrivate: true,
			expectNil:    true,
		},
		{
			name: "override allow private CIDR",
			rule: EgressRule{
				ToFQDNS:         []FQDN{"private.com"},
				BlockPrivateIPs: boolPtr(true), // overrides global
			},
			ipMap: map[FQDN]*FQDNStatus{
				"private.com": {
					Addresses: []string{MustCIDR("192.168.0.1/32").String()},
				},
			},
			blockPrivate: false,
			expectNil:    true,
		},
		{
			name: "includes ports in result",
			rule: EgressRule{
				ToFQDNS: []FQDN{"test.com"},
				Ports: []netv1.NetworkPolicyPort{
					{Port: intStrPtr(443)},
				},
			},
			ipMap: map[FQDN]*FQDNStatus{
				"test.com": {
					Addresses: []string{MustCIDR("1.2.3.4/32").String()},
				},
			},
			blockPrivate: false,
			expectCIDRs:  []string{"1.2.3.4/32"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := tt.rule
			result := rule.toNetworkPolicyEgressRule(tt.ipMap, tt.blockPrivate)
			if tt.expectNil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
				var cidrs []string
				for _, peer := range result.To {
					if peer.IPBlock != nil {
						cidrs = append(cidrs, peer.IPBlock.CIDR)
					}
				}
				assert.ElementsMatch(t, tt.expectCIDRs, cidrs)
				if len(rule.Ports) > 0 {
					assert.Equal(t, rule.Ports, result.Ports)
				}
			}
		})
	}
}

func Test_NetworkPolicy_FQDNs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		policy   NetworkPolicy
		expected []FQDN
	}{
		{
			name: "no FQDNs",
			policy: NetworkPolicy{
				Spec: NetworkPolicySpec{},
			},
			expected: nil,
		},
		{
			name: "only egress FQDNs",
			policy: NetworkPolicy{
				Spec: NetworkPolicySpec{
					Egress: []EgressRule{
						{ToFQDNS: []FQDN{"x.com", "y.com"}},
						{ToFQDNS: []FQDN{"y.com", "z.com"}},
					},
				},
			},
			expected: []FQDN{"x.com", "y.com", "z.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.policy.FQDNs()
			assert.ElementsMatch(t, tt.expected, result)
		})
	}
}

func Test_NetworkPolicy_ToNetworkPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		np         NetworkPolicy
		statuses   []FQDNStatus
		expectNil  bool
		wantEgress []string
	}{
		{
			name: "no egress rules",
			np: NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "empty", Namespace: "default"},
				Spec: NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{},
				},
			},
			statuses:  []FQDNStatus{},
			expectNil: true,
		},
		{
			name: "one public CIDR in egress",
			np: NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "egress-only", Namespace: "default"},
				Spec: NetworkPolicySpec{
					PodSelector:     metav1.LabelSelector{},
					Egress:          []EgressRule{{ToFQDNS: []FQDN{"b.com"}}},
					BlockPrivateIPs: true,
				},
			},
			statuses: []FQDNStatus{
				{FQDN: "b.com", Addresses: []string{MustCIDR("1.1.1.1/32").String()}},
			},
			wantEgress: []string{"1.1.1.1/32"},
		},
		{
			name: "egress with only private IPs",
			np: NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "both-private", Namespace: "default"},
				Spec: NetworkPolicySpec{
					PodSelector:     metav1.LabelSelector{},
					Egress:          []EgressRule{{ToFQDNS: []FQDN{"b.com"}}},
					BlockPrivateIPs: true,
				},
			},
			statuses: []FQDNStatus{
				{FQDN: "b.com", Addresses: []string{MustCIDR("10.0.0.1/32").String()}},
			},
			wantEgress: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.np.ToNetworkPolicy(tt.statuses)
			if tt.expectNil {
				assert.Nil(t, result)
				return
			}
			assert.NotNil(t, result)

			var gotEgress []string
			for _, rule := range result.Spec.Egress {
				for _, peer := range rule.To {
					if peer.IPBlock != nil {
						gotEgress = append(gotEgress, peer.IPBlock.CIDR)
					}
				}
			}
			assert.ElementsMatch(t, tt.wantEgress, gotEgress)

			var wantTypes []netv1.PolicyType
			// We want to block all traffic if egress was defined, even if all IPs were filtered out
			if len(tt.np.Spec.Egress) > 0 {
				wantTypes = append(wantTypes, netv1.PolicyTypeEgress)
			}
			assert.ElementsMatch(t, wantTypes, result.Spec.PolicyTypes)
		})
	}
}

func Test_FQDNStatus_Update(t *testing.T) {
	now := metav1.Now()
	past := metav1.NewTime(now.Add(-2 * time.Hour))

	tests := []struct {
		name                string
		initial             FQDNStatus
		cidrs               []*CIDR
		reason              NetworkPolicyResolveConditionReason
		message             string
		retryTimeoutSeconds int
		expectCleared       bool
		expectAddresses     []string
		expectReason        NetworkPolicyResolveConditionReason
	}{
		{
			name: "Success updates addresses and timestamps",
			initial: FQDNStatus{
				ResolveReason:      NetworkPolicyResolveTemporaryError,
				LastSuccessfulTime: past,
				LastTransitionTime: past,
			},
			cidrs:               []*CIDR{MustCIDR("1.2.3.4/32")},
			reason:              NetworkPolicyResolveSuccess,
			message:             "ok",
			retryTimeoutSeconds: 3600,
			expectCleared:       false,
			expectAddresses:     []string{"1.2.3.4/32"},
			expectReason:        NetworkPolicyResolveSuccess,
		},
		{
			name: "Transient error before timeout does not clear addresses",
			initial: FQDNStatus{
				Addresses:          []string{"5.6.7.8/32"},
				LastSuccessfulTime: metav1.NewTime(time.Now()),
				ResolveReason:      NetworkPolicyResolveSuccess,
			},
			cidrs:               nil,
			reason:              NetworkPolicyResolveTemporaryError,
			message:             "temporary error",
			retryTimeoutSeconds: 3600,
			expectCleared:       false,
			expectAddresses:     []string{"5.6.7.8/32"},
			expectReason:        NetworkPolicyResolveTemporaryError,
		},
		{
			name: "Transient error after timeout clears addresses",
			initial: FQDNStatus{
				Addresses:          []string{"5.6.7.8/32"},
				LastSuccessfulTime: metav1.NewTime(time.Now().Add(-2 * time.Hour)),
				ResolveReason:      NetworkPolicyResolveSuccess,
			},
			cidrs:               nil,
			reason:              NetworkPolicyResolveTemporaryError,
			message:             "timeout hit",
			retryTimeoutSeconds: 3600,
			expectCleared:       true,
			expectAddresses:     []string{},
			expectReason:        NetworkPolicyResolveTemporaryError,
		},
		{
			name: "Non-transient error clears addresses immediately",
			initial: FQDNStatus{
				Addresses:          []string{"5.6.7.8/32"},
				LastSuccessfulTime: metav1.NewTime(time.Now()),
				ResolveReason:      NetworkPolicyResolveSuccess,
			},
			cidrs:               nil,
			reason:              NetworkPolicyResolveDomainNotFound,
			message:             "NXDOMAIN",
			retryTimeoutSeconds: 3600,
			expectCleared:       true,
			expectAddresses:     []string{},
			expectReason:        NetworkPolicyResolveDomainNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleared := tt.initial.Update(tt.cidrs, tt.reason, tt.message, tt.retryTimeoutSeconds)
			assert.Equal(t, tt.expectCleared, cleared)
			assert.Equal(t, tt.expectAddresses, tt.initial.Addresses)
			assert.Equal(t, tt.expectReason, tt.initial.ResolveReason)
			assert.Equal(t, tt.message, tt.initial.ResolveMessage)
		})
	}
}

func Test_NewFQDNStatus(t *testing.T) {
	fqdn := FQDN("example.com")
	cidrs := []*CIDR{
		MustCIDR("1.2.3.4/32"),
		MustCIDR("5.6.7.8/32"),
	}
	reason := NetworkPolicyResolveSuccess
	message := "resolved successfully"

	status := NewFQDNStatus(fqdn, cidrs, reason, message)

	assert.Equal(t, fqdn, status.FQDN)
	assert.Equal(t, reason, status.ResolveReason)
	assert.Equal(t, message, status.ResolveMessage)
	assert.Equal(t, []string{"1.2.3.4/32", "5.6.7.8/32"}, status.Addresses)

	// Verify timestamps are set and equal
	assert.False(t, status.LastSuccessfulTime.IsZero(), "LastSuccessfulTime should be set")
	assert.False(t, status.LastTransitionTime.IsZero(), "LastTransitionTime should be set")
	assert.Equal(t, status.LastSuccessfulTime, status.LastTransitionTime, "Times should be equal on creation")
}

func Test_FQDNStatusList_LookupTable(t *testing.T) {
	status1 := FQDNStatus{
		FQDN:               "example.com",
		LastSuccessfulTime: metav1.Now(),
		ResolveReason:      NetworkPolicyResolveSuccess,
		Addresses:          []string{"1.1.1.1/32"},
	}
	status2 := FQDNStatus{
		FQDN:               "google.com",
		LastSuccessfulTime: metav1.Now(),
		ResolveReason:      NetworkPolicyResolveTemporaryError,
		Addresses:          []string{"8.8.8.8/32"},
	}

	statusList := FQDNStatusList{status1, status2}
	table := statusList.LookupTable()

	assert.Len(t, table, 2)

	assert.Contains(t, table, FQDN("example.com"))
	assert.Contains(t, table, FQDN("google.com"))

	// Check that the pointers are correct
	assert.Equal(t, &status1, table["example.com"])
	assert.Equal(t, &status2, table["google.com"])
}
