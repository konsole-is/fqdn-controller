package network

import (
	"context"
	"errors"
	"fmt"
	"github.com/konsole-is/fqdn-controller/api/v1alpha1"
	"net"
	"sync"
	"time"
)

// DNSResolverResult Is the resulting outcome of a Resolver's DNS lookup
type DNSResolverResult struct {
	// Domain that the lookup was for
	Domain v1alpha1.FQDN
	// Error that the lookup may have caused
	Error error
	// CIDRs found for the given domain if no error occurred
	CIDRs []v1alpha1.CIDR
}

// IsError returns true if the result is an error
func (dlr *DNSResolverResult) IsError() bool {
	return dlr.Error != nil
}

// ErrorReason returns the reason for the error if the result is an error
func (dlr *DNSResolverResult) ErrorReason() v1alpha1.NetworkPolicyResolveConditionReason {
	if dlr.Error == nil {
		return v1alpha1.NetworkPolicyResolveSuccess
	}
	var lookupErr *lookupError
	if errors.As(dlr.Error, &lookupErr) {
		return lookupErr.Reason
	}
	var dnsErr *net.DNSError
	if !errors.As(dlr.Error, &dnsErr) {
		return v1alpha1.NetworkPolicyResolveOtherError
	}
	if dnsErr.IsTimeout {
		return v1alpha1.NetworkPolicyResolveTimeout
	}
	if dnsErr.IsNotFound {
		return v1alpha1.NetworkPolicyResolveTimeout
	}
	if dnsErr.IsTemporary {
		return v1alpha1.NetworkPolicyResolveTemporaryError
	}
	return v1alpha1.NetworkPolicyResolveOtherError
}

// ErrorMessage returns the error message for the result
func (dlr *DNSResolverResult) ErrorMessage() string {
	if dlr.Error == nil {
		return ""
	}
	var lookupErr *lookupError
	if errors.As(dlr.Error, &lookupErr) {
		return lookupErr.Error()
	}
	var dnsErr *net.DNSError
	if !errors.As(dlr.Error, &dnsErr) {
		return dlr.Error.Error()
	}
	if dnsErr.IsTimeout {
		return fmt.Sprintf("Timeout waiting for DNS lookup for %s", dlr.Domain)
	}
	if dnsErr.IsNotFound {
		return fmt.Sprintf("DNS resolution for %s not found (NXDOMAIN)", dlr.Domain)
	}
	if dnsErr.IsTemporary {
		return fmt.Sprintf("Temporary failure in name resolution for %s", dlr.Domain)
	}
	return dlr.Error.Error()
}

// DNSResolverResultList is a wrapper around DNSResolver result with helpful getter methods
type DNSResolverResultList []*DNSResolverResult

func (dlr DNSResolverResultList) CIDRs() []v1alpha1.CIDR {
	var cidrs []v1alpha1.CIDR
	for _, dr := range dlr {
		cidrs = append(cidrs, dr.CIDRs...)
	}
	return cidrs
}

func (dlr DNSResolverResultList) Errors() []*DNSResolverResult {
	var results []*DNSResolverResult
	for _, dr := range dlr {
		if dr.IsError() {
			results = append(results, dr)
		}
	}
	return results
}

func (dlr DNSResolverResultList) AggregatedErrorReason() v1alpha1.NetworkPolicyResolveConditionReason {
	reason := v1alpha1.NetworkPolicyResolveSuccess
	for _, dr := range dlr {
		current := dr.ErrorReason()
		if current.Priority() > reason.Priority() {
			reason = current
		}
	}
	return reason
}

func (dlr DNSResolverResultList) AggregatedErrorMessage() string {
	reason := v1alpha1.NetworkPolicyResolveSuccess
	message := ""
	for _, dr := range dlr {
		if dr.IsError() {
			current := dr.ErrorReason()
			if current.Priority() > reason.Priority() {
				reason = current
				message = dr.ErrorMessage()
			}
		}
	}
	return message
}

func (dlr DNSResolverResultList) CIDRLookupTable() map[v1alpha1.FQDN][]v1alpha1.CIDR {
	lookup := make(map[v1alpha1.FQDN][]v1alpha1.CIDR)
	for _, dr := range dlr {
		if !dr.IsError() {
			lookup[dr.Domain] = dr.CIDRs
		}
	}
	return lookup
}

func (dlr DNSResolverResultList) ErrorLookupTable() map[v1alpha1.FQDN]string {
	lookup := make(map[v1alpha1.FQDN]string)
	for _, dr := range dlr {
		if dr.IsError() {
			lookup[dr.Domain] = dr.ErrorMessage()
		}
	}
	return lookup
}

type Resolver interface {
	LookupIP(ctx context.Context, network string, host string) ([]net.IP, error)
}

// DNSResolver resolves domains to IPs
type DNSResolver struct {
	networkType v1alpha1.NetworkType
	resolver    Resolver
}

type lookupError struct {
	Reason  v1alpha1.NetworkPolicyResolveConditionReason
	Message string
}

func (e lookupError) Error() string {
	return e.Message
}

// lookupIP resolves the host to its underlying IP addresses
func (r *DNSResolver) lookupIP(ctx context.Context, host v1alpha1.FQDN) ([]v1alpha1.CIDR, error) {
	if !host.Valid() {
		return nil, &lookupError{
			Reason:  v1alpha1.NetworkPolicyResolveInvalidDomain,
			Message: fmt.Sprintf("Received invalid FQDN '%s'", host),
		}
	}
	ips, err := r.resolver.LookupIP(ctx, r.networkType.ResolverString(), string(host))
	if err != nil {
		return nil, err
	}
	var cidrs []v1alpha1.CIDR
	for _, ip := range ips {
		cidrs = append(cidrs, v1alpha1.CIDR{IP: ip, Range: 32})
	}
	return cidrs, nil
}

// Resolve all the given fqdns to a DNSResolverResult
func (r *DNSResolver) Resolve(fqdns []v1alpha1.FQDN, timeout time.Duration) DNSResolverResultList {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	results := make(chan *DNSResolverResult)

	var wg sync.WaitGroup
	for _, fqdn := range fqdns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cidrs, err := r.lookupIP(ctx, fqdn)
			results <- &DNSResolverResult{Error: err, Domain: fqdn, CIDRs: cidrs}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var lookupResults []*DNSResolverResult

	for res := range results {
		lookupResults = append(lookupResults, res)
	}

	return DNSResolverResultList(lookupResults)
}

// NewDNSResolver returns the default resolver to use for DNS lookup
func NewDNSResolver(networkType v1alpha1.NetworkType) DNSResolver {
	return DNSResolver{
		networkType: networkType,
		resolver:    &net.Resolver{},
	}
}
