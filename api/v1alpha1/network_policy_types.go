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
// +kubebuilder:validation:Pattern=`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`
type FQDN string

// IngressRule defines rules for inbound network traffic from the specified FQDNs on the specified ports
// Each FQDNs IP's will be looked up periodically to update the underlying NetworkPolicy
type IngressRule struct {
	// Ports describes the ports to allow traffic on
	Ports []netv1.NetworkPolicyPort `json:"ports"`
	// FromFQDNS are the FQDNs from which traffic is allowed (incoming)
	// +kubebuilder:validation:MaxItems=20
	FromFQDNS []FQDN `json:"fromFQDNS"`
	// BlockPrivateIPs when set, overwrites the default behavior of the same field in NetworkPolicySpec
	BlockPrivateIPs *bool `json:"blockPrivateIPs,omitempty"`
}

// EgressRule defines rules for outbound network traffic to the specified FQDNs on the specified ports
// Each FQDNs IP's will be looked up periodically to update the underlying NetworkPolicy
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
	// Options are 'all', 'ipv4' or 'ipv6'
	// +kubebuilder:default:=ipv4
	EnabledNetworkType NetworkType `json:"enabledNetworkType,omitempty"`
	// TTLSeconds The refresh interval on FQDN IP lookups
	// +kubebuilder:validation:Minimum=60
	// +kubebuilder:validation:Maximum=1800
	// +kubebuilder:default:=300
	TTLSeconds int32 `json:"ttlSeconds,omitempty"`
	// ResolveTimeoutSeconds The timeout to use for lookups on the FQDNs
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=60
	// +kubebuilder:default:=3
	ResolveTimeoutSeconds int32 `json:"resolveTimeoutSeconds,omitempty"`
	// BlockPrivateIPs Ensures that any private IPs are emitted from the rules
	// +kubebuilder:default:=true
	BlockPrivateIPs bool `json:"blockPrivateIPs,omitempty"`
}

// NetworkPolicyStatus defines the observed state of NetworkPolicy.
type NetworkPolicyStatus struct {
	// LatestLookupTime The last time the IPs were resolved
	LatestLookupTime metav1.Time `json:"latestLookupTime,omitempty"`

	// LatestErrors Maps FQDN's to correlated lookup errors in the last resolve
	LatestErrors map[FQDN]NetworkPolicyResolveConditionReason `json:"latestErrors,omitempty"`

	// CurrentAddressCount Counts the number of valid IPs applied in the generated network policy
	CurrentAddressCount int32 `json:"CurrentAddressCount,omitempty"`

	// BlockedAddressCount Counts the number of IPs excluded from the network policy due to being private
	BlockedAddressCount int32 `json:"blockedAddressCount,omitempty"`

	// TotalAddressCount The number of total IPs resolved from the FQDNs before filtering
	TotalAddressCount int32 `json:"totalAddressesCount,omitempty"`

	// ResolvedAddresses Lists the currently resolved addresses. Note that they may not all be applied to the network
	// policy due to being private and blocked. Check the underlying network policy to get the exact addresses applied.
	ResolvedAddresses map[FQDN][]string `json:"resolvedAddresses,omitempty"`

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

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// NetworkPolicy is the Schema for the networkpolicies API.
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
