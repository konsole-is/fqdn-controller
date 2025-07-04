package utils

import (
	"github.com/konsole-is/fqdn-controller/api/v1alpha1"
	netv1 "k8s.io/api/networking/v1"
)

// UniqueCidrsInNetworkPolicy returns all the unique CIDR's applied in the network policy
func UniqueCidrsInNetworkPolicy(networkPolicy *netv1.NetworkPolicy) []*v1alpha1.CIDR {
	if networkPolicy == nil {
		return []*v1alpha1.CIDR{}
	}

	set := make(map[string]struct{})
	for _, rule := range networkPolicy.Spec.Ingress {
		for _, from := range rule.From {
			if from.IPBlock != nil {
				set[from.IPBlock.CIDR] = struct{}{}
			}
		}
	}
	for _, rule := range networkPolicy.Spec.Egress {
		for _, to := range rule.To {
			if to.IPBlock != nil {
				set[to.IPBlock.CIDR] = struct{}{}
			}
		}
	}
	var cidrs []*v1alpha1.CIDR
	for cidr := range set {
		if c, err := v1alpha1.NewCIDR(cidr); err == nil {
			cidrs = append(cidrs, c)
		}
	}
	return cidrs
}
