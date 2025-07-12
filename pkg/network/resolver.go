package network

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/konsole-is/fqdn-controller/api/v1alpha1"
)

type lookupError struct {
	Reason  v1alpha1.NetworkPolicyResolveConditionReason
	Message string
}

func (e lookupError) Error() string {
	return e.Message
}

// DNSResolverResult Is the resulting outcome of a Resolver's DNS lookup
type DNSResolverResult struct {
	// Domain that the lookup was for
	Domain v1alpha1.FQDN
	// Error that the lookup may have caused
	Error error
	// Resolve status
	Status v1alpha1.NetworkPolicyResolveConditionReason
	// Message for the reason
	Message string
	// CIDRs found for the given domain if no error occurred
	CIDRs []*v1alpha1.CIDR
}

// resolveReason returns the reason for the status of the resolve result
func resolveReason(err error) v1alpha1.NetworkPolicyResolveConditionReason {
	if err == nil {
		return v1alpha1.NetworkPolicyResolveSuccess
	}
	var lookupErr *lookupError
	if errors.As(err, &lookupErr) {
		return lookupErr.Reason
	}
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) {
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

// resolveMessage returns an error message for the given error
func resolveMessage(err error) string {
	if err == nil {
		return "Resolve succeeded"
	}
	var lookupErr *lookupError
	if errors.As(err, &lookupErr) {
		return lookupErr.Error()
	}
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) {
		return err.Error()
	}
	if dnsErr.IsTimeout {
		return "Timeout waiting for DNS response"
	}
	if dnsErr.IsNotFound {
		return "Domain not found"
	}
	if dnsErr.IsTemporary {
		return "Temporary failure in name resolution"
	}
	return err.Error()
}

// DNSResolverResultList is a wrapper around DNSResolver result with helpful getter methods
type DNSResolverResultList []*DNSResolverResult

// CIDRs returns all the CIDRs in the result list
func (dlr DNSResolverResultList) CIDRs() []*v1alpha1.CIDR {
	var cidrs []*v1alpha1.CIDR
	for _, dr := range dlr {
		cidrs = append(cidrs, dr.CIDRs...)
	}
	return cidrs
}

// AggregatedResolveStatus returns the reason with the highest priority in the result list
func (dlr DNSResolverResultList) AggregatedResolveStatus() v1alpha1.NetworkPolicyResolveConditionReason {
	reason := v1alpha1.NetworkPolicyResolveSuccess
	for _, dr := range dlr {
		current := dr.Status
		if current.Priority() > reason.Priority() {
			reason = current
		}
	}
	return reason
}

// AggregatedResolveMessage returns the message with the highest priority in the result list
func (dlr DNSResolverResultList) AggregatedResolveMessage() string {
	reason := v1alpha1.NetworkPolicyResolveSuccess
	message := ""
	for _, dr := range dlr {
		current := dr.Status
		if message == "" || current.Priority() > reason.Priority() {
			reason = current
			message = dr.Message
		}
	}
	return message
}

// LookupTable returns a FQDN lookup table for the result list
func (dlr DNSResolverResultList) LookupTable() map[v1alpha1.FQDN]*DNSResolverResult {
	lookup := make(map[v1alpha1.FQDN]*DNSResolverResult)
	for _, dr := range dlr {
		lookup[dr.Domain] = dr
	}
	return lookup
}

type Resolver interface {
	LookupIP(ctx context.Context, network string, host string) ([]net.IP, error)
}

// DNSResolver resolves domains to IPs
type DNSResolver struct {
	resolver Resolver
}

// NewDNSResolver returns the default resolver to use for DNS lookup
func NewDNSResolver() *DNSResolver {
	return &DNSResolver{
		resolver: &net.Resolver{},
	}
}

// lookupIP resolves the host to its underlying IP addresses
func (r *DNSResolver) lookupIP(
	ctx context.Context,
	networkType v1alpha1.NetworkType,
	host v1alpha1.FQDN,
) ([]*v1alpha1.CIDR, error) {
	if !host.Valid() {
		return nil, &lookupError{
			Reason:  v1alpha1.NetworkPolicyResolveInvalidDomain,
			Message: fmt.Sprintf("Received invalid FQDN '%s'", host),
		}
	}
	ips, err := r.resolver.LookupIP(ctx, networkType.ResolverString(), string(host))
	if err != nil {
		return nil, err
	}
	var cidrs []*v1alpha1.CIDR
	for _, ip := range ips {
		prefix := 128
		if ip.To4() != nil {
			prefix = 32
		}
		cidrs = append(cidrs, &v1alpha1.CIDR{IP: ip, Prefix: prefix})
	}
	return cidrs, nil
}

// Resolve all the given fqdns to a DNSResolverResult
//   - maxConcurrent controls how many goroutines are spawned to resolve addresses from FQDNs
func (r *DNSResolver) Resolve(
	ctx context.Context,
	timeout time.Duration,
	maxConcurrent int,
	networkType v1alpha1.NetworkType,
	fqdns []v1alpha1.FQDN,
) DNSResolverResultList {
	results := make(chan *DNSResolverResult)
	sem := make(chan struct{}, maxConcurrent)

	var wg sync.WaitGroup
	for _, fqdn := range fqdns {
		wg.Add(1)
		go func(rFQDN v1alpha1.FQDN) {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
				// acquired a slot
				defer func() { <-sem }()
			case <-ctx.Done():
				// parent context cancelled before acquiring slot
				return
			}

			childCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			cidrs, err := r.lookupIP(childCtx, networkType, rFQDN)

			select {
			case results <- &DNSResolverResult{
				Domain:  rFQDN,
				Error:   err,
				Status:  resolveReason(err),
				Message: resolveMessage(err),
				CIDRs:   cidrs,
			}:
			case <-ctx.Done():
				// context cancelled while trying to send
			}
		}(fqdn)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var lookupResults []*DNSResolverResult
	for res := range results {
		lookupResults = append(lookupResults, res)
	}
	return lookupResults
}

type FakeDNSResolver struct {
	Results DNSResolverResultList
}

func (r *FakeDNSResolver) Resolve(
	_ context.Context,
	_ time.Duration,
	_ int,
	_ v1alpha1.NetworkType,
	_ []v1alpha1.FQDN,
) DNSResolverResultList {
	return r.Results
}
