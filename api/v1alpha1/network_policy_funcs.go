package v1alpha1

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

func isAllowed(cidrString string, globalBlock bool, ruleBlock *bool) bool {
	blockPrivateIP := globalBlock
	if ruleBlock != nil {
		blockPrivateIP = *ruleBlock
	}
	cidr, err := NewCIDR(cidrString)
	if err != nil {
		return false
	}
	if cidr.IsPrivate() && blockPrivateIP {
		return false
	}
	return true
}

func getPeers(fqdns []FQDN, ips map[FQDN]*FQDNStatus, globalBlock bool, ruleBlock *bool) []netv1.NetworkPolicyPeer {
	var peers []netv1.NetworkPolicyPeer

	for _, fqdn := range fqdns {
		if status, ok := ips[fqdn]; ok {
			for _, addr := range status.Addresses {
				if isAllowed(addr, globalBlock, ruleBlock) {
					peers = append(peers, netv1.NetworkPolicyPeer{IPBlock: &netv1.IPBlock{
						CIDR: addr,
					}})
				}
			}
		}
	}
	return peers
}

// toNetworkPolicyEgressRule converts the EgressRule to a netv1.NetworkPolicyEgressRule.
// Returns nil if no peers were found.
func (r *EgressRule) toNetworkPolicyEgressRule(ips map[FQDN]*FQDNStatus, blockPrivate bool) *netv1.NetworkPolicyEgressRule {
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
// If no Egress rules are specified, nil is returned.
func (np *NetworkPolicy) ToNetworkPolicy(fqdnStatuses []FQDNStatus) *netv1.NetworkPolicy {
	var policies []netv1.PolicyType
	if len(np.Spec.Egress) > 0 {
		policies = append(policies, netv1.PolicyTypeEgress)
	}
	if len(policies) == 0 {
		return nil
	}
	lookup := FQDNStatusList(fqdnStatuses).LookupTable()
	var egress []netv1.NetworkPolicyEgressRule
	for _, fqdnRule := range np.Spec.Egress {
		if rule := fqdnRule.toNetworkPolicyEgressRule(lookup, np.Spec.BlockPrivateIPs); rule != nil {
			egress = append(egress, *rule)
		}
	}

	return &netv1.NetworkPolicy{
		ObjectMeta: np.ObjectMeta,
		Spec: netv1.NetworkPolicySpec{
			PodSelector: np.Spec.PodSelector,
			Egress:      egress,
			PolicyTypes: policies,
		},
	}
}

// Update updates the status of the FQDN.
// If addresses were cleared due to an error during the update, the method returns true.
func (f *FQDNStatus) Update(
	cidrs []*CIDR, reason NetworkPolicyResolveConditionReason, message string, retryTimeoutSeconds int,
) bool {
	cleared := false
	if reason == NetworkPolicyResolveSuccess {
		f.LastSuccessfulTime = metav1.Now()
		f.Addresses = CIDRList(cidrs).String()
	}
	// On transient errors we want to adhere to the retry timeout specification
	if reason != NetworkPolicyResolveSuccess && reason.Transient() {
		retryLimitReached := time.Now().After(
			f.LastSuccessfulTime.Add(time.Duration(retryTimeoutSeconds) * time.Second),
		)

		if retryLimitReached {
			f.Addresses = []string{}
			cleared = true
		}
	}
	// On non-transient errors we clear the addresses immediately
	if reason != NetworkPolicyResolveSuccess && !reason.Transient() {
		f.Addresses = []string{}
		cleared = true
	}
	if f.ResolveReason != reason {
		f.LastTransitionTime = metav1.Now()
	}
	f.ResolveReason = reason
	f.ResolveMessage = message
	return cleared
}

func NewFQDNStatus(fqdn FQDN, cidrs []*CIDR, reason NetworkPolicyResolveConditionReason, message string) FQDNStatus {
	timeNow := metav1.Now()
	return FQDNStatus{
		FQDN:               fqdn,
		LastSuccessfulTime: timeNow,
		LastTransitionTime: timeNow,
		ResolveReason:      reason,
		ResolveMessage:     message,
		Addresses:          CIDRList(cidrs).String(),
	}
}

type FQDNStatusList []FQDNStatus

func (s FQDNStatusList) LookupTable() map[FQDN]*FQDNStatus {
	lookupTable := make(map[FQDN]*FQDNStatus)
	for _, status := range s {
		lookupTable[status.FQDN] = &status
	}
	return lookupTable
}
