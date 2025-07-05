package v1alpha1

import (
	"context"
	"fmt"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net"
	"regexp"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"strings"
	"time"
)

// CIDR represents a network range in CIDR (Classless Inter-Domain Routing) notation.
// It consists of an IP address and a Prefix (prefix length) that defines the size of the network.
type CIDR struct {
	IP     net.IP
	Prefix int
}

func NewCIDR(cidr string) (*CIDR, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	prefix, _ := ipNet.Mask.Size()
	return &CIDR{
		IP:     ip,
		Prefix: prefix,
	}, nil
}

func MustCIDR(cidr string) *CIDR {
	if c, err := NewCIDR(cidr); err != nil {
		panic(err)
	} else {
		return c
	}
}

// String returns the string representation of the CIDR
func (c *CIDR) String() string {
	return fmt.Sprintf("%s/%d", c.IP.String(), c.Prefix)
}

// IsPrivate returns true if the CIDR is a private address
func (c *CIDR) IsPrivate() bool {
	return c.IP.IsPrivate()
}

type CIDRList []*CIDR

func (l CIDRList) String() []string {
	var result []string
	for _, cidr := range l {
		result = append(result, cidr.String())
	}
	return result
}

// Valid returns true if the FQDN is valid
func (f *FQDN) Valid() bool {
	labelRegexp := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)
	labels := strings.Split(string(*f), ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || !labelRegexp.MatchString(label) {
			return false
		}
	}
	return true
}

func isAllowed(cidr *CIDR, globalBlock bool, ruleBlock *bool) bool {
	blockPrivateIP := globalBlock
	if ruleBlock != nil {
		blockPrivateIP = *ruleBlock
	}
	if cidr.IsPrivate() && blockPrivateIP {
		return false
	}
	return true
}

func getPeers(fqdns []FQDN, ips map[FQDN][]*CIDR, globalBlock bool, ruleBlock *bool) []netv1.NetworkPolicyPeer {
	var peers []netv1.NetworkPolicyPeer

	for _, fqdn := range fqdns {
		if cidrs, ok := ips[fqdn]; ok {
			for _, cidr := range cidrs {
				if isAllowed(cidr, globalBlock, ruleBlock) {
					peers = append(peers, netv1.NetworkPolicyPeer{IPBlock: &netv1.IPBlock{
						CIDR: cidr.String(),
					}})
				} else {
					logger := logf.FromContext(context.Background())
					logger.Info("NOT ALLOWED", "fqdn", fqdn, "cidr", cidr, "globalBlock", globalBlock, "ruleBlock", ruleBlock)
				}
			}
		}
	}
	return peers
}

// toNetworkPolicyIngressRule converts the IngressRule to a netv1.NetworkPolicyIngressRule.
// Returns nil if no peers were found.
func (r *IngressRule) toNetworkPolicyIngressRule(ips map[FQDN][]*CIDR, blockPrivate bool) *netv1.NetworkPolicyIngressRule {
	peers := getPeers(r.FromFQDNS, ips, blockPrivate, r.BlockPrivateIPs)
	if len(peers) == 0 {
		return nil
	}

	return &netv1.NetworkPolicyIngressRule{
		Ports: r.Ports,
		From:  peers,
	}
}

// toNetworkPolicyEgressRule converts the EgressRule to a netv1.NetworkPolicyEgressRule.
// Returns nil if no peers were found.
func (r *EgressRule) toNetworkPolicyEgressRule(ips map[FQDN][]*CIDR, blockPrivate bool) *netv1.NetworkPolicyEgressRule {
	peers := getPeers(r.ToFQDNS, ips, blockPrivate, r.BlockPrivateIPs)
	if len(peers) == 0 {
		return nil
	}

	return &netv1.NetworkPolicyEgressRule{
		Ports: r.Ports,
		To:    peers,
	}
}

// FQDNs Returns all unique FQDNs defined in the network policy
func (np *NetworkPolicy) FQDNs() []FQDN {
	var set = make(map[FQDN]struct{})
	for _, rule := range np.Spec.Ingress {
		for _, fqdn := range rule.FromFQDNS {
			set[fqdn] = struct{}{}
		}
	}
	for _, rule := range np.Spec.Egress {
		for _, fqdn := range rule.ToFQDNS {
			set[fqdn] = struct{}{}
		}
	}

	var fqdns []FQDN
	for fqdn := range set {
		fqdns = append(fqdns, fqdn)
	}
	return fqdns
}

// ToNetworkPolicy converts the NetworkPolicy to a netv1.NetworkPolicy.
// Returns nil if neither ingress rules nor egress rules were available.
// This is to conform with how netv1.NetworkPolicy works: When no ingress nor egress rules are specified, the
// PolicyTypes defaults to ["Ingress"] which in turn blocks all ingress traffic which is not what we want to do.
func (np *NetworkPolicy) ToNetworkPolicy(ips map[FQDN][]*CIDR) *netv1.NetworkPolicy {
	var ingress []netv1.NetworkPolicyIngressRule
	for _, fqdnRule := range np.Spec.Ingress {
		if rule := fqdnRule.toNetworkPolicyIngressRule(ips, np.Spec.BlockPrivateIPs); rule != nil {
			ingress = append(ingress, *rule)
		}
	}
	var egress []netv1.NetworkPolicyEgressRule
	for _, fqdnRule := range np.Spec.Egress {
		if rule := fqdnRule.toNetworkPolicyEgressRule(ips, np.Spec.BlockPrivateIPs); rule != nil {
			egress = append(egress, *rule)
		}
	}
	if len(ingress) == 0 && len(egress) == 0 {
		return nil
	}
	var policies []netv1.PolicyType
	if len(ingress) > 0 {
		policies = append(policies, netv1.PolicyTypeIngress)
	}
	if len(egress) > 0 {
		policies = append(policies, netv1.PolicyTypeEgress)
	}

	return &netv1.NetworkPolicy{
		ObjectMeta: np.ObjectMeta,
		Spec: netv1.NetworkPolicySpec{
			PodSelector: np.Spec.PodSelector,
			Ingress:     ingress,
			Egress:      egress,
			PolicyTypes: policies,
		},
	}
}

// ResolveResultMap Maps FQDN's to their resolved IP addresses
type ResolveResultMap map[FQDN][]*CIDR

// String converts the map cidrs to strings
func (m ResolveResultMap) String() map[FQDN][]string {
	result := make(map[FQDN][]string)
	for k, v := range m {
		result[k] = CIDRList(v).String()
	}
	return result
}

// SetStatusFields Updates all status fields apart from ObservedGeneration and Conditions.
func (s *NetworkPolicyStatus) SetStatusFields(
	allCidrs []*CIDR, appliedCidrs []*CIDR,
	resolveResults map[FQDN][]*CIDR,
// errors map[FQDN]NetworkPolicyResolveConditionReason,
) {
	s.TotalAddressCount = int32(len(allCidrs))
	s.AppliedAddressCount = int32(len(appliedCidrs))
	s.BlockedAddressCount = int32(len(allCidrs) - len(appliedCidrs))
	s.ResolvedAddresses = ResolveResultMap(resolveResults).String()
	//s.LookupErrors = errors
	s.LatestLookupTime = metav1.NewTime(time.Now())
}
