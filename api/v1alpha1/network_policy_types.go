/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NetworkType defines the available ip address types to resolve
//
//   - Options are one of: 'all', 'ipv4', 'ipv6'
//
// +kubebuilder:validation:Enum=all;ipv4;ipv6
type NetworkType string

const (
	All  NetworkType = "all"
	Ipv4 NetworkType = "ipv4"
	Ipv6 NetworkType = "ipv6"
)

// ResolverString returns the string value that net.Resolver expects in LookupIP.
// Returns an empty string for unknown types.
func (n NetworkType) ResolverString() string {
	switch n {
	case All:
		return "ip"
	case Ipv4:
		return "ip4"
	case Ipv6:
		return "ip6"
	}
	return ""
}

// FQDN is short for Fully Qualified Domain Name and represents a complete domain name that uniquely identifies a host
// on the internet. It must consist of one or more labels separated by dots (e.g., "api.example.com"), where each label
// can contain letters, digits, and hyphens, but cannot start or end with a hyphen. The FQDN must end with a top-level
// domain (e.g., ".com", ".org") of at least two characters.
//
// +kubebuilder:validation:Pattern=`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`
type FQDN string

// IngressRule defines rules for inbound network traffic from the specified FQDNs on the specified ports.
// Each FQDN is resolved periodically to IPs, and those IPs are used to update the underlying NetworkPolicy.
//
// # USAGE NOTICE
//
// Kubernetes does not typically preserve the original source IP of incoming external traffic.
// Traffic entering through cloud LoadBalancers (e.g. AWS ALB/NLB) most often has the source IP replaced by that of the
// LoadBalancer or node. While preserving the original IP is possible (e.g. using NLB with proxy protocol),
// such configurations are advanced and non-default and come with their own limitations.
//
// Because of this, using FQDN-based ingress rules is only effective when the source traffic comes from
// trusted environments where source IPs are preserved end-to-end, for example:
//   - Direct VPC peers with custom routing
//   - VPN tunnels terminating directly in the cluster's network
//   - NodePort services accessed directly
//
// In most cases, standard ingress rules using pod or namespace selectors should be preferred.
// Only use FQDN-based ingress when you are certain the source IP will be preserved and DNS-based matching is required.
type IngressRule struct {
	// Ports describes the ports to allow traffic on
	Ports []netv1.NetworkPolicyPort `json:"ports"`
	// FromFQDNS are the FQDNs from which traffic is allowed (incoming)
	// +kubebuilder:validation:MaxItems=20
	FromFQDNS []FQDN `json:"fromFQDNS"`
	// BlockPrivateIPs when set, overwrites the default behavior of the same field in NetworkPolicySpec
	BlockPrivateIPs *bool `json:"blockPrivateIPs,omitempty"`
}

// EgressRule defines rules for outbound network traffic to the specified FQDNs on the specified ports.
// Each FQDNs IP's will be looked up periodically to update the underlying NetworkPolicy.
type EgressRule struct {
	// Ports describes the ports to allow traffic on
	Ports []netv1.NetworkPolicyPort `json:"ports"`
	// ToFQDNS are the FQDNs to which traffic is allowed (outgoing)
	// +kubebuilder:validation:MaxItems=20
	ToFQDNS []FQDN `json:"toFQDNS"`
	// BlockPrivateIPs when set, overwrites the default behavior of the same field in NetworkPolicySpec
	BlockPrivateIPs *bool `json:"blockPrivateIPs,omitempty"`
}

// NetworkPolicySpec defines the desired state of NetworkPolicy.
type NetworkPolicySpec struct {
	// PodSelector defines which pods this network policy shall apply to
	PodSelector metav1.LabelSelector `json:"podSelector"`
	// Ingress defines the incoming network traffic rules for the selected pods
	Ingress []IngressRule `json:"ingress,omitempty"`
	// Egress defines the outbound network traffic rules for the selected pods
	Egress []EgressRule `json:"egress,omitempty"`
	// EnabledNetworkType defines which type of IP addresses to allow.
	//
	//  - Options are one of: 'all', 'ipv4', 'ipv6'
	//  - Defaults to 'ipv4' if not specified
	//
	// +kubebuilder:default:=ipv4
	EnabledNetworkType NetworkType `json:"enabledNetworkType,omitempty"`
	// TTLSeconds The interval at which the IP addresses of the FQDNs are re-evaluated.
	//
	//  - Defaults to 60 seconds if not specified.
	//  - Maximum value is 1800 seconds.
	//  - Minimum value is 5 seconds.
	//  - Must be greater than ResolveTimeoutSeconds.
	//
	// +kubebuilder:validation:Minimum=5
	// +kubebuilder:validation:Maximum=1800
	// +kubebuilder:default:=60
	TTLSeconds int32 `json:"ttlSeconds,omitempty"`
	// ResolveTimeoutSeconds The timeout to use for lookups of the FQDNs
	//
	//  - Defaults to 3 seconds if not specified.
	//  - Maximum value is 60 seconds.
	//  - Minimum value is 1 second.
	//  - Must be less than TTLSeconds.
	//
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=60
	// +kubebuilder:default:=3
	ResolveTimeoutSeconds int32 `json:"resolveTimeoutSeconds,omitempty"`
	// RetryTimeoutSeconds How long the resolving of an individual FQDN should be retried in case of errors before being
	// removed from the underlying network policy. This ensures intermittent failures in name resolution do not clear
	// existing addresses causing unwanted service disruption.
	//
	//  - Defaults to 3600 (1 hour) if not specified (nil)
	//  - Maximum value is 86400 (24 hours)
	//
	// +kubebuilder:validation:Maximum=86400
	// +kubebuilder:default:=3600
	RetryTimeoutSeconds *int32 `json:"retryTimeoutSeconds,omitempty"`
	// BlockPrivateIPs When set to true, all private IPs are emitted from the rules unless otherwise specified at the
	// IngressRule or EgressRule level.
	//
	// - Defaults to false if not specified
	BlockPrivateIPs bool `json:"blockPrivateIPs,omitempty"`
}

// FQDNStatus defines the status of a given FQDN
type FQDNStatus struct {
	// FQDN the FQDN this status refers to
	FQDN FQDN `json:"fqdn"`
	// LastSuccessfulTime is the last time the FQDN was resolved successfully. I.e. the last time the ResolveReason was
	// NetworkPolicyResolveSuccess
	LastSuccessfulTime metav1.Time `json:"LastSuccessfulTime,omitempty"`
	// LastTransitionTime is the last time the reason changed
	LastTransitionTime metav1.Time `json:"lastTransitionTime,omitempty"`
	// ResolveReason describes the last resolve status
	ResolveReason NetworkPolicyResolveConditionReason `json:"resolveReason,omitempty"`
	// ResolveMessage a message describing the reason for the status
	ResolveMessage string `json:"resolveMessage,omitempty"`
	// Addresses is the list of resolved addresses for the given FQDN.
	// The list is cleared if LastSuccessfulTime exceeds the time limit specified by
	// NetworkPolicySpec.RetryTimeoutSeconds
	Addresses []string `json:"addresses,omitempty"`
}

// NetworkPolicyStatus defines the observed state of NetworkPolicy.
type NetworkPolicyStatus struct {
	// LatestLookupTime The last time the IPs were resolved
	LatestLookupTime metav1.Time `json:"latestLookupTime,omitempty"`

	// FQDNs lists the status of each FQDN in the network policy
	FQDNs []FQDNStatus `json:"fqdns,omitempty"`

	// AppliedAddressCount Counts the number of unique IPs applied in the generated network policy
	AppliedAddressCount int32 `json:"appliedAddressCount,omitempty"`

	// TotalAddressCount The number of total IPs resolved from the FQDNs before filtering
	TotalAddressCount int32 `json:"totalAddressesCount,omitempty"`

	Conditions         []metav1.Condition `json:"conditions"`
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
}

type NetworkPolicyConditionType string

const (
	NetworkPolicyReadyCondition   NetworkPolicyConditionType = "Ready"
	NetworkPolicyResolveCondition NetworkPolicyConditionType = "Resolve"
)

type NetworkPolicyReadyConditionReason string

const (
	NetworkPolicyReady      NetworkPolicyReadyConditionReason = "Ready"
	NetworkPolicyEmptyRules NetworkPolicyReadyConditionReason = "EmptyRules"
	NetworkPolicyFailed     NetworkPolicyReadyConditionReason = "Failed"
)

type NetworkPolicyResolveConditionReason string

const (
	NetworkPolicyResolveOtherError     NetworkPolicyResolveConditionReason = "OTHER_ERROR"
	NetworkPolicyResolveInvalidDomain  NetworkPolicyResolveConditionReason = "INVALID_DOMAIN"
	NetworkPolicyResolveDomainNotFound NetworkPolicyResolveConditionReason = "NXDOMAIN"
	NetworkPolicyResolveTimeout        NetworkPolicyResolveConditionReason = "TIMEOUT"
	NetworkPolicyResolveTemporaryError NetworkPolicyResolveConditionReason = "TEMPORARY"
	NetworkPolicyResolveUnknown        NetworkPolicyResolveConditionReason = "UNKNOWN"
	NetworkPolicyResolveSuccess        NetworkPolicyResolveConditionReason = "SUCCESS"
)

func (r NetworkPolicyResolveConditionReason) Priority() int {
	switch r {
	case NetworkPolicyResolveOtherError:
		return 6
	case NetworkPolicyResolveInvalidDomain:
		return 5
	case NetworkPolicyResolveDomainNotFound:
		return 4
	case NetworkPolicyResolveTimeout:
		return 3
	case NetworkPolicyResolveTemporaryError:
		return 2
	case NetworkPolicyResolveUnknown:
		return 1
	default:
		return 0
	}
}

func (r NetworkPolicyResolveConditionReason) Transient() bool {
	switch r {
	case NetworkPolicyResolveInvalidDomain:
		return false
	case NetworkPolicyResolveDomainNotFound:
		return false
	default:
		return true
	}
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// NetworkPolicy is the Schema for the networkpolicies API.
//
//   - Please ensure the pods you apply this network policy to have a separate policy allowing
//     access to CoreDNS / KubeDNS pods in your cluster. Without this, once this Network policy is applied, access to
//     DNS will be blocked due to how network policies deny all unspecified traffic by default once applied.
//   - If no addresses are resolved from the FQDNs from either Ingress or Egress rules that were specified, the default
//     behavior is to block all traffic of that type. This conforms with the default behavior of network policies
//     (networking.k8s.io/v1)
//
// +kubebuilder:resource:path=fqdnnetworkpolicies,shortName=fqdn,singular=fqdnnetworkpolicy,scope=Namespaced
type NetworkPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NetworkPolicySpec   `json:"spec,omitempty"`
	Status NetworkPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// NetworkPolicyList contains a list of NetworkPolicy.
type NetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NetworkPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NetworkPolicy{}, &NetworkPolicyList{})
}
