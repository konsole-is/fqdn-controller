package network

import (
	"context"
	"errors"
	"fmt"
	"github.com/konsole-is/fqdn-controller/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	"net"
	"testing"
	"time"
)

func TestDNSResolverResult_IsError(t *testing.T) {
	result := &DNSResolverResult{}
	assert.False(t, result.IsError(), "expected no error")

	result.Error = errors.New("fail")
	assert.True(t, result.IsError(), "expected error")
}

func TestDNSResolverResult_ErrorReason(t *testing.T) {
	domain := v1alpha1.FQDN("test.com")

	tests := []struct {
		name     string
		input    *DNSResolverResult
		expected v1alpha1.NetworkPolicyResolveConditionReason
	}{
		{
			name:     "no error",
			input:    &DNSResolverResult{Domain: domain},
			expected: v1alpha1.NetworkPolicyResolveSuccess,
		},
		{
			name: "lookupError with reason",
			input: &DNSResolverResult{
				Domain: domain,
				Error:  &lookupError{Reason: v1alpha1.NetworkPolicyResolveInvalidDomain},
			},
			expected: v1alpha1.NetworkPolicyResolveInvalidDomain,
		},
		{
			name: "dns timeout error",
			input: &DNSResolverResult{
				Domain: domain,
				Error: &net.DNSError{
					IsTimeout: true,
				},
			},
			expected: v1alpha1.NetworkPolicyResolveTimeout,
		},
		{
			name: "dns not found",
			input: &DNSResolverResult{
				Domain: domain,
				Error: &net.DNSError{
					IsNotFound: true,
				},
			},
			expected: v1alpha1.NetworkPolicyResolveTimeout, // your logic maps this too
		},
		{
			name: "dns temporary",
			input: &DNSResolverResult{
				Domain: domain,
				Error: &net.DNSError{
					IsTemporary: true,
				},
			},
			expected: v1alpha1.NetworkPolicyResolveTemporaryError,
		},
		{
			name: "other error",
			input: &DNSResolverResult{
				Domain: domain,
				Error:  errors.New("something went wrong"),
			},
			expected: v1alpha1.NetworkPolicyResolveOtherError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.input.ErrorReason())
		})
	}
}

func TestDNSResolverResult_ErrorMessage(t *testing.T) {
	domain := v1alpha1.FQDN("foo.test")

	tests := []struct {
		name     string
		input    *DNSResolverResult
		expected string
	}{
		{
			name:     "no error",
			input:    &DNSResolverResult{Domain: domain},
			expected: "",
		},
		{
			name: "lookupError",
			input: &DNSResolverResult{
				Domain: domain,
				Error:  &lookupError{Reason: v1alpha1.NetworkPolicyResolveDomainNotFound, Message: "lookup error"},
			},
			expected: "lookup error",
		},
		{
			name: "dns timeout",
			input: &DNSResolverResult{
				Domain: domain,
				Error: &net.DNSError{
					IsTimeout: true,
				},
			},
			expected: fmt.Sprintf("Timeout waiting for DNS lookup for %s", domain),
		},
		{
			name: "dns not found",
			input: &DNSResolverResult{
				Domain: domain,
				Error: &net.DNSError{
					IsNotFound: true,
				},
			},
			expected: fmt.Sprintf("DNS resolution for %s not found (NXDOMAIN)", domain),
		},
		{
			name: "dns temporary",
			input: &DNSResolverResult{
				Domain: domain,
				Error: &net.DNSError{
					IsTemporary: true,
				},
			},
			expected: fmt.Sprintf("Temporary failure in name resolution for %s", domain),
		},
		{
			name: "generic error",
			input: &DNSResolverResult{
				Domain: domain,
				Error:  errors.New("something else failed"),
			},
			expected: "something else failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.input.ErrorMessage())
		})
	}
}

func makeCIDR(ip string) *v1alpha1.CIDR {
	c, _ := v1alpha1.NewCIDR(ip)
	return c
}

func Test_DNSResolverResultList_CIDRs(t *testing.T) {
	list := DNSResolverResultList{
		{CIDRs: []*v1alpha1.CIDR{makeCIDR("1.1.1.1/32")}},
		{CIDRs: []*v1alpha1.CIDR{makeCIDR("2.2.2.2/32")}},
	}
	cidrs := list.CIDRs()
	assert.Len(t, cidrs, 2)
	assert.Equal(t, "1.1.1.1", cidrs[0].IP.String())
	assert.Equal(t, "2.2.2.2", cidrs[1].IP.String())
}

func Test_DNSResolverResultList_Errors(t *testing.T) {
	list := DNSResolverResultList{
		{Domain: "ok.com"},
		{Domain: "fail.com", Error: errors.New("failed")},
	}
	errs := list.Errors()
	assert.Len(t, errs, 1)
	assert.Equal(t, v1alpha1.FQDN("fail.com"), errs[0].Domain)
}

func Test_DNSResolverResultList_AggregatedErrorReason(t *testing.T) {
	list := DNSResolverResultList{
		{Error: &net.DNSError{IsTemporary: true}},
		{Error: &net.DNSError{IsTimeout: true}}, // Higher Priority
	}
	reason := list.AggregatedErrorReason()
	assert.Equal(t, v1alpha1.NetworkPolicyResolveTimeout, reason)
}

func Test_DNSResolverResultList_AggregatedErrorMessage(t *testing.T) {
	list := DNSResolverResultList{
		{Domain: "a.test", Error: &net.DNSError{IsTemporary: true}},
		{Domain: "b.test", Error: &net.DNSError{IsTimeout: true}}, // Higher priority
	}
	msg := list.AggregatedErrorMessage()
	assert.Contains(t, msg, "Timeout")
	assert.Contains(t, msg, "b.test")
}

func Test_DNSResolverResultList_CIDRLookupTable(t *testing.T) {
	list := DNSResolverResultList{
		{Domain: "ok.com", CIDRs: []*v1alpha1.CIDR{makeCIDR("8.8.8.8/32")}},
		{Domain: "fail.com", Error: errors.New("bad")},
	}
	table := list.CIDRLookupTable()
	assert.Len(t, table, 1)
	assert.Contains(t, table, v1alpha1.FQDN("ok.com"))
}

func Test_DNSResolverResultList_ErrorLookupTable(t *testing.T) {
	list := DNSResolverResultList{
		{Domain: "ok.com"},
		{Domain: "fail.com", Error: &net.DNSError{IsTimeout: true}},
	}
	table := list.ErrorLookupTable()
	assert.Len(t, table, 1)
	assert.Equal(t, v1alpha1.NetworkPolicyResolveTimeout, table["fail.com"])
}

// fakeResolver returns a predefined list of IPs and an optional error.
type fakeResolver struct {
	results []net.IP
	err     error
}

func (f *fakeResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	return f.results, f.err
}

func Test_lookupIP_withFakeResolver(t *testing.T) {
	tests := []struct {
		name        string
		fqdn        v1alpha1.FQDN
		networkType v1alpha1.NetworkType
		resolver    *fakeResolver
		expectCIDRs []string
		expectErr   bool
	}{
		{
			name:        "invalid FQDN",
			fqdn:        "invalid_fqdn", // invalid because missing dot, etc.
			networkType: v1alpha1.All,
			resolver:    &fakeResolver{results: nil},
			expectErr:   true,
		},
		{
			name:        "resolver returns error",
			fqdn:        "example.com",
			networkType: v1alpha1.All,
			resolver:    &fakeResolver{err: errors.New("mocked DNS error")},
			expectErr:   true,
		},
		{
			name:        "successful IP lookup",
			fqdn:        "example.com",
			networkType: v1alpha1.All,
			resolver: &fakeResolver{
				results: []net.IP{
					net.ParseIP("1.2.3.4"),
					net.ParseIP("5.6.7.8"),
				},
			},
			expectCIDRs: []string{"1.2.3.4/32", "5.6.7.8/32"},
			expectErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &DNSResolver{
				resolver: tt.resolver,
			}

			cidrs, err := r.lookupIP(context.Background(), tt.networkType, tt.fqdn)

			if tt.expectErr {
				assert.Error(t, err)
				assert.Nil(t, cidrs)
			} else {
				assert.NoError(t, err)
				var got []string
				for _, c := range cidrs {
					got = append(got, c.String())
				}
				assert.ElementsMatch(t, tt.expectCIDRs, got)
			}
		})
	}
}

// fnFakeResolver mocks the Resolver interface
type fnFakeResolver struct {
	lookupFunc func(ctx context.Context, network, host string) ([]net.IP, error)
}

func (f *fnFakeResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	return f.lookupFunc(ctx, network, host)
}

func TestDNSResolver_Resolve(t *testing.T) {
	t.Run("successful resolution", func(t *testing.T) {
		fake := &fnFakeResolver{
			lookupFunc: func(ctx context.Context, network, host string) ([]net.IP, error) {
				return []net.IP{net.ParseIP("1.2.3.4")}, nil
			},
		}

		resolver := &DNSResolver{resolver: fake}
		result := resolver.Resolve([]v1alpha1.FQDN{"example.com"}, time.Second, v1alpha1.Ipv4)

		assert.Len(t, result, 1)
		assert.False(t, result[0].IsError())
		assert.Equal(t, "example.com", string(result[0].Domain))
		assert.Len(t, result[0].CIDRs, 1)
		assert.Equal(t, "1.2.3.4", result[0].CIDRs[0].IP.String())
	})

	t.Run("invalid FQDN returns lookupError", func(t *testing.T) {
		// Invalid FQDN that will fail `Valid()`
		invalidFQDN := v1alpha1.FQDN("")

		fake := &fnFakeResolver{
			lookupFunc: func(ctx context.Context, network, host string) ([]net.IP, error) {
				return []net.IP{}, nil // won't be used
			},
		}

		resolver := &DNSResolver{resolver: fake}
		result := resolver.Resolve([]v1alpha1.FQDN{invalidFQDN}, time.Second, v1alpha1.All)

		assert.Len(t, result, 1)
		assert.True(t, result[0].IsError())
		assert.Equal(t, invalidFQDN, result[0].Domain)

		var lookupErr *lookupError
		assert.True(t, errors.As(result[0].Error, &lookupErr))
		assert.Equal(t, v1alpha1.NetworkPolicyResolveInvalidDomain, lookupErr.Reason)
	})

	t.Run("timeout returns context error", func(t *testing.T) {
		fake := &fnFakeResolver{
			lookupFunc: func(ctx context.Context, network, host string) ([]net.IP, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			},
		}

		resolver := &DNSResolver{resolver: fake}
		start := time.Now()
		result := resolver.Resolve([]v1alpha1.FQDN{"timeout.com"}, 100*time.Millisecond, v1alpha1.All)
		elapsed := time.Since(start)

		assert.Less(t, elapsed, 500*time.Millisecond, "Should timeout early")
		assert.Len(t, result, 1)
		assert.True(t, result[0].IsError())
		assert.True(t, errors.Is(result[0].Error, context.DeadlineExceeded))
	})
}
