package v1alpha1

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"net"
	"testing"
	"time"
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
		cidr               *CIDR
		isAllowed          bool
	}{
		{
			name:               "global true, rule nil (private IP)",
			globalBlockPrivate: true,
			ruleBlockPrivate:   nil,
			cidr:               MustCIDR("192.168.1.1/32"),
			isAllowed:          false,
		},
		{
			name:               "global false, rule nil (private IP)",
			globalBlockPrivate: false,
			ruleBlockPrivate:   nil,
			cidr:               MustCIDR("192.168.1.1/32"),
			isAllowed:          true,
		},
		{
			name:               "global true, rule false (private IP)",
			globalBlockPrivate: true,
			ruleBlockPrivate:   &falseVal,
			cidr:               MustCIDR("192.168.1.1/32"),
			isAllowed:          true,
		},
		{
			name:               "global false, rule true (private IP)",
			globalBlockPrivate: false,
			ruleBlockPrivate:   &trueVal,
			cidr:               MustCIDR("192.168.1.1/32"),
			isAllowed:          false,
		},
		{
			name:               "public IP always allowed",
			globalBlockPrivate: true,
			ruleBlockPrivate:   nil,
			cidr:               MustCIDR("8.8.8.8/32"),
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
	makeCIDR := func(ip string, prefix int) *CIDR {
		return &CIDR{
			IP:     net.ParseIP(ip),
			Prefix: prefix,
		}
	}

	trueVal := true
	falseVal := false

	tests := []struct {
		name        string
		fqdns       []FQDN
		ips         map[FQDN][]*CIDR
		globalBlock bool
		ruleBlock   *bool
		expected    []string
	}{
		{
			name:        "include private and public",
			fqdns:       []FQDN{"example.com"},
			globalBlock: false,
			ruleBlock:   nil,
			ips: map[FQDN][]*CIDR{
				"example.com": {
					makeCIDR("192.168.1.1", 32),
					makeCIDR("8.8.8.8", 32),
				},
			},
			expected: []string{"192.168.1.1/32", "8.8.8.8/32"},
		},
		{
			name:        "exclude private",
			fqdns:       []FQDN{"example.com"},
			globalBlock: true,
			ruleBlock:   nil,
			ips: map[FQDN][]*CIDR{
				"example.com": {
					makeCIDR("192.168.1.1", 32),
					makeCIDR("8.8.8.8", 32),
				},
			},
			expected: []string{"8.8.8.8/32"},
		},
		{
			name:        "no matching FQDN",
			fqdns:       []FQDN{"missing.com"},
			globalBlock: true,
			ruleBlock:   nil,
			ips: map[FQDN][]*CIDR{
				"example.com": {makeCIDR("1.1.1.1", 32)},
			},
			expected: []string{},
		},
		{
			name:        "multiple FQDNs with mixed IPs",
			fqdns:       []FQDN{"example.com", "google.com"},
			globalBlock: true,
			ruleBlock:   nil,
			ips: map[FQDN][]*CIDR{
				"example.com": {makeCIDR("8.8.8.8", 32)},
				"google.com": {
					makeCIDR("10.0.0.1", 32),
					makeCIDR("1.1.1.1", 32),
				},
			},
			expected: []string{"8.8.8.8/32", "1.1.1.1/32"},
		},
		{
			name:        "rule override: allow private despite global block",
			fqdns:       []FQDN{"example.com"},
			globalBlock: true,
			ruleBlock:   &falseVal,
			ips: map[FQDN][]*CIDR{
				"example.com": {
					makeCIDR("10.0.0.1", 32),
					makeCIDR("8.8.4.4", 32),
				},
			},
			expected: []string{"10.0.0.1/32", "8.8.4.4/32"},
		},
		{
			name:        "rule override: block private even if global allows",
			fqdns:       []FQDN{"example.com"},
			globalBlock: false,
			ruleBlock:   &trueVal,
			ips: map[FQDN][]*CIDR{
				"example.com": {
					makeCIDR("10.0.0.1", 32),
					makeCIDR("1.1.1.1", 32),
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

func Test_IngressRule_toNetworkPolicyIngressRule(t *testing.T) {
	tests := []struct {
		name         string
		rule         IngressRule
		ipMap        map[FQDN][]*CIDR
		blockPrivate bool
		expectNil    bool
		expectCIDRs  []string
	}{
		{
			name: "no matching FQDNs, returns nil",
			rule: IngressRule{
				FromFQDNS: []FQDN{"missing.com"},
			},
			ipMap:        map[FQDN][]*CIDR{},
			blockPrivate: false,
			expectNil:    true,
		},
		{
			name: "one public CIDR allowed (blockPrivate = false)",
			rule: IngressRule{
				FromFQDNS: []FQDN{"public.com"},
			},
			ipMap: map[FQDN][]*CIDR{
				"public.com": {MustCIDR("8.8.8.8/32")},
			},
			blockPrivate: false,
			expectCIDRs:  []string{"8.8.8.8/32"},
		},
		{
			name: "private CIDR excluded by default (blockPrivate = true)",
			rule: IngressRule{
				FromFQDNS: []FQDN{"private.com"},
			},
			ipMap: map[FQDN][]*CIDR{
				"private.com": {MustCIDR("192.168.0.1/32")},
			},
			blockPrivate: true,
			expectNil:    true,
		},
		{
			name: "override blockPrivate = true (should exclude private)",
			rule: IngressRule{
				FromFQDNS:       []FQDN{"private.com"},
				BlockPrivateIPs: boolPtr(true),
			},
			ipMap: map[FQDN][]*CIDR{
				"private.com": {MustCIDR("192.168.0.1/32")},
			},
			blockPrivate: false,
			expectNil:    true,
		},
		{
			name: "override blockPrivate = false (should allow private)",
			rule: IngressRule{
				FromFQDNS:       []FQDN{"private.com"},
				BlockPrivateIPs: boolPtr(false),
			},
			ipMap: map[FQDN][]*CIDR{
				"private.com": {MustCIDR("192.168.0.1/32")},
			},
			blockPrivate: true,
			expectCIDRs:  []string{"192.168.0.1/32"},
		},
		{
			name: "includes ports in result",
			rule: IngressRule{
				FromFQDNS: []FQDN{"test.com"},
				Ports: []netv1.NetworkPolicyPort{
					{Port: intStrPtr(80)},
				},
			},
			ipMap: map[FQDN][]*CIDR{
				"test.com": {MustCIDR("1.2.3.4/32")},
			},
			blockPrivate: false,
			expectCIDRs:  []string{"1.2.3.4/32"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := tt.rule
			result := rule.toNetworkPolicyIngressRule(tt.ipMap, tt.blockPrivate)
			if tt.expectNil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
				var cidrs []string
				for _, peer := range result.From {
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

func Test_EgressRule_toNetworkPolicyEgressRule(t *testing.T) {
	tests := []struct {
		name         string
		rule         EgressRule
		ipMap        map[FQDN][]*CIDR
		blockPrivate bool
		expectNil    bool
		expectCIDRs  []string
	}{
		{
			name: "no matching FQDNs, returns nil",
			rule: EgressRule{
				ToFQDNS: []FQDN{"missing.com"},
			},
			ipMap:        map[FQDN][]*CIDR{},
			blockPrivate: false,
			expectNil:    true,
		},
		{
			name: "one public CIDR allowed",
			rule: EgressRule{
				ToFQDNS: []FQDN{"public.com"},
			},
			ipMap: map[FQDN][]*CIDR{
				"public.com": {MustCIDR("8.8.8.8/32")},
			},
			blockPrivate: false,
			expectCIDRs:  []string{"8.8.8.8/32"},
		},
		{
			name: "private CIDR excluded by default",
			rule: EgressRule{
				ToFQDNS: []FQDN{"private.com"},
			},
			ipMap: map[FQDN][]*CIDR{
				"private.com": {MustCIDR("192.168.0.1/32")},
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
			ipMap: map[FQDN][]*CIDR{
				"private.com": {MustCIDR("192.168.0.1/32")},
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
			ipMap: map[FQDN][]*CIDR{
				"test.com": {MustCIDR("1.2.3.4/32")},
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
			name: "only ingress FQDNs",
			policy: NetworkPolicy{
				Spec: NetworkPolicySpec{
					Ingress: []IngressRule{
						{FromFQDNS: []FQDN{"a.com", "b.com"}},
						{FromFQDNS: []FQDN{"b.com", "c.com"}},
					},
				},
			},
			expected: []FQDN{"a.com", "b.com", "c.com"},
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
		{
			name: "combined ingress and egress with overlap",
			policy: NetworkPolicy{
				Spec: NetworkPolicySpec{
					Ingress: []IngressRule{
						{FromFQDNS: []FQDN{"a.com", "b.com"}},
					},
					Egress: []EgressRule{
						{ToFQDNS: []FQDN{"b.com", "c.com"}},
					},
				},
			},
			expected: []FQDN{"a.com", "b.com", "c.com"},
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
		name        string
		np          NetworkPolicy
		ips         map[FQDN][]*CIDR
		expectNil   bool
		wantIngress []string
		wantEgress  []string
	}{
		{
			name: "no ingress or egress rules",
			np: NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "empty", Namespace: "default"},
				Spec: NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{},
				},
			},
			ips:       map[FQDN][]*CIDR{},
			expectNil: true,
		},
		{
			name: "one public CIDR in ingress",
			np: NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "ingress-only", Namespace: "default"},
				Spec: NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{},
					Ingress: []IngressRule{
						{FromFQDNS: []FQDN{"a.com"}},
					},
					BlockPrivateIPs: true,
				},
			},
			ips: map[FQDN][]*CIDR{
				"a.com": {MustCIDR("8.8.8.8/32")},
			},
			wantIngress: []string{"8.8.8.8/32"},
		},
		{
			name: "one public CIDR in egress",
			np: NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "egress-only", Namespace: "default"},
				Spec: NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{},
					Egress: []EgressRule{
						{ToFQDNS: []FQDN{"b.com"}},
					},
					BlockPrivateIPs: true,
				},
			},
			ips: map[FQDN][]*CIDR{
				"b.com": {MustCIDR("1.1.1.1/32")},
			},
			wantEgress: []string{"1.1.1.1/32"},
		},
		{
			name: "both ingress and egress with valid public IPs",
			np: NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "both-valid", Namespace: "default"},
				Spec: NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{},
					Ingress: []IngressRule{
						{FromFQDNS: []FQDN{"a.com"}},
					},
					Egress: []EgressRule{
						{ToFQDNS: []FQDN{"b.com"}},
					},
					BlockPrivateIPs: true,
				},
			},
			ips: map[FQDN][]*CIDR{
				"a.com": {MustCIDR("8.8.8.8/32")},
				"b.com": {MustCIDR("1.1.1.1/32")},
			},
			wantIngress: []string{"8.8.8.8/32"},
			wantEgress:  []string{"1.1.1.1/32"},
		},
		{
			name: "both ingress and egress with only private IPs",
			np: NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "both-private", Namespace: "default"},
				Spec: NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{},
					Ingress: []IngressRule{
						{FromFQDNS: []FQDN{"a.com"}},
					},
					Egress: []EgressRule{
						{ToFQDNS: []FQDN{"b.com"}},
					},
					BlockPrivateIPs: true,
				},
			},
			ips: map[FQDN][]*CIDR{
				"a.com": {MustCIDR("192.168.0.1/32")},
				"b.com": {MustCIDR("10.0.0.1/32")},
			},
			expectNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.np.ToNetworkPolicy(tt.ips)
			if tt.expectNil {
				assert.Nil(t, result)
				return
			}
			assert.NotNil(t, result)

			var gotIngress, gotEgress []string
			for _, rule := range result.Spec.Ingress {
				for _, peer := range rule.From {
					if peer.IPBlock != nil {
						gotIngress = append(gotIngress, peer.IPBlock.CIDR)
					}
				}
			}
			for _, rule := range result.Spec.Egress {
				for _, peer := range rule.To {
					if peer.IPBlock != nil {
						gotEgress = append(gotEgress, peer.IPBlock.CIDR)
					}
				}
			}
			assert.ElementsMatch(t, tt.wantIngress, gotIngress)
			assert.ElementsMatch(t, tt.wantEgress, gotEgress)

			var wantTypes []netv1.PolicyType
			if len(tt.wantIngress) > 0 {
				wantTypes = append(wantTypes, netv1.PolicyTypeIngress)
			}
			if len(tt.wantEgress) > 0 {
				wantTypes = append(wantTypes, netv1.PolicyTypeEgress)
			}
			assert.ElementsMatch(t, wantTypes, result.Spec.PolicyTypes)
		})
	}
}

func Test_ResolveResultMap_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    ResolveResultMap
		expected map[FQDN][]string
	}{
		{
			name: "single fqdn with single CIDR",
			input: ResolveResultMap{
				"example.com": {MustCIDR("1.1.1.1/32")},
			},
			expected: map[FQDN][]string{
				"example.com": {"1.1.1.1/32"},
			},
		},
		{
			name: "single fqdn with multiple CIDRs",
			input: ResolveResultMap{
				"example.org": {
					MustCIDR("192.168.1.0/24"),
					MustCIDR("10.0.0.1/32"),
				},
			},
			expected: map[FQDN][]string{
				"example.org": {"192.168.1.0/24", "10.0.0.1/32"},
			},
		},
		{
			name: "multiple fqdn entries",
			input: ResolveResultMap{
				"a.com": {MustCIDR("8.8.8.8/32")},
				"b.com": {MustCIDR("1.1.1.1/32")},
			},
			expected: map[FQDN][]string{
				"a.com": {"8.8.8.8/32"},
				"b.com": {"1.1.1.1/32"},
			},
		},
		{
			name:     "empty map",
			input:    ResolveResultMap{},
			expected: map[FQDN][]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := tt.input.String()
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func Test_NetworkPolicyStatus_SetStatus(t *testing.T) {
	t.Parallel()

	allCidrs := []*CIDR{
		MustCIDR("10.0.0.1/32"),
		MustCIDR("192.168.1.1/32"),
	}
	appliedCidrs := []*CIDR{
		MustCIDR("10.0.0.1/32"),
	}
	resolveResults := map[FQDN][]*CIDR{
		"test.com": allCidrs,
	}
	errors := map[FQDN]NetworkPolicyResolveConditionReason{
		"fail.com": NetworkPolicyResolveTimeout,
	}

	var status NetworkPolicyStatus
	before := time.Now()
	status.SetStatusFields(allCidrs, appliedCidrs, resolveResults, errors)

	assert.Equal(t, int32(1), status.AppliedAddressCount)
	assert.Equal(t, int32(1), status.BlockedAddressCount)
	assert.Equal(t, map[FQDN][]string{
		"test.com": {"10.0.0.1/32", "192.168.1.1/32"},
	}, status.ResolvedAddresses)
	assert.Equal(t, errors, status.LatestErrors)
	assert.WithinDuration(t, before, status.LatestLookupTime.Time, time.Second)
}
