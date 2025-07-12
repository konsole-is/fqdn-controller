package utils

import (
	"github.com/konsole-is/fqdn-controller/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
)

func TCPNetworkPolicyPort(port int, endPort int) netv1.NetworkPolicyPort {
	return netv1.NetworkPolicyPort{
		Protocol: ptr.To(corev1.ProtocolTCP),
		Port:     ptr.To(intstr.FromInt32(int32(port))),
		EndPort:  ptr.To(int32(endPort)),
	}
}

func TCPEgressRule(fqdns []v1alpha1.FQDN, ports []int) v1alpha1.EgressRule {
	var policyPorts []netv1.NetworkPolicyPort
	for _, port := range ports {
		policyPorts = append(policyPorts, TCPNetworkPolicyPort(port, port))
	}
	return v1alpha1.EgressRule{
		Ports:   policyPorts,
		ToFQDNS: fqdns,
	}
}

func PodSelector(key string, value string) metav1.LabelSelector {
	return metav1.LabelSelector{
		MatchLabels: map[string]string{
			key: value,
		},
	}
}
