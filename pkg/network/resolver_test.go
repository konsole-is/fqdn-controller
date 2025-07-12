package network

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/konsole-is/fqdn-controller/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDNSResolverResult_resolveReason(t *testing.T) {
	tests := []struct {
		name     string
		input    error
		expected v1alpha1.NetworkPolicyResolveConditionReason
	}{
		{
			name:     "no error",
			input:    nil,
			expected: v1alpha1.NetworkPolicyResolveSuccess,
		},
		{
			name:     "lookupError with reason",
			input:    &lookupError{Reason: v1alpha1.NetworkPolicyResolveInvalidDomain},
			expected: v1alpha1.NetworkPolicyResolveInvalidDomain,
		},
		{
			name: "dns timeout error",
			input: &net.DNSError{
				IsTimeout: true,
			},
			expected: v1alpha1.NetworkPolicyResolveTimeout,
		},
		{
			name: "dns not found",
			input: &net.DNSError{
				IsNotFound: true,
			},
			expected: v1alpha1.NetworkPolicyResolveTimeout, // your logic maps this too
		},
		{
			name: "dns temporary",
			input: &net.DNSError{
				IsTemporary: true,
			},
			expected: v1alpha1.NetworkPolicyResolveTemporaryError,
		},
		{
			name:     "other error",
			input:    errors.New("something went wrong"),
			expected: v1alpha1.NetworkPolicyResolveOtherError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, resolveReason(tt.input))
		})
	}
}

func TestDNSResolverResult_reasonMessage(t *testing.T) {
	tests := []struct {
		name     string
		input    error
		expected string
	}{
		{
			name:     "no error",
			input:    nil,
			expected: "Resolve succeeded",
		},
		{
			name:     "lookupError",
			input:    &lookupError{Reason: v1alpha1.NetworkPolicyResolveDomainNotFound, Message: "lookup error"},
			expected: "lookup error",
		},
		{
			name: "dns timeout",
			input: &net.DNSError{
				IsTimeout: true,
			},
			expected: "Timeout waiting for DNS response",
		},
		{
			name: "dns not found",
			input: &net.DNSError{
				IsNotFound: true,
			},
			expected: "Domain not found",
		},
		{
			name: "dns temporary",
			input: &net.DNSError{
				IsTemporary: true,
			},
			expected: "Temporary failure in name resolution",
		},
		{
			name:     "generic error",
			input:    errors.New("something else failed"),
			expected: "something else failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, resolveMessage(tt.input))
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

func Test_DNSResolverResultList_AggregatedResolveReason(t *testing.T) {
	list := DNSResolverResultList{
		{Status: v1alpha1.NetworkPolicyResolveSuccess},
		{Status: v1alpha1.NetworkPolicyResolveOtherError}, // Highest Priority
		{Status: v1alpha1.NetworkPolicyResolveTemporaryError},
		{Status: v1alpha1.NetworkPolicyResolveSuccess},
	}
	reason := list.AggregatedResolveStatus()
	assert.Equal(t, v1alpha1.NetworkPolicyResolveOtherError, reason)
}

func Test_DNSResolverResultList_AggregatedResolveMessage(t *testing.T) {
	list := DNSResolverResultList{
		{Status: v1alpha1.NetworkPolicyResolveSuccess, Message: "Not this"},
		{Status: v1alpha1.NetworkPolicyResolveOtherError, Message: "This"}, // Highest Priority
		{Status: v1alpha1.NetworkPolicyResolveTemporaryError, Message: "Not this"},
		{Status: v1alpha1.NetworkPolicyResolveSuccess, Message: "Not this"},
	}
	msg := list.AggregatedResolveMessage()
	assert.Contains(t, msg, "This")
}

func Test_DNSResolverResultList_LookupTable(t *testing.T) {
	list := DNSResolverResultList{
		{Domain: "ok.com", CIDRs: []*v1alpha1.CIDR{makeCIDR("8.8.8.8/32")}},
		{Domain: "fail.com", Error: errors.New("bad")},
	}
	table := list.LookupTable()
	assert.Len(t, table, 2)
	assert.Contains(t, table, v1alpha1.FQDN("ok.com"))
	assert.Equal(t, v1alpha1.FQDN("ok.com"), table["ok.com"].Domain)
	assert.Contains(t, table, v1alpha1.FQDN("fail.com"))
	assert.Equal(t, v1alpha1.FQDN("fail.com"), table["fail.com"].Domain)
}

// fakeResolver returns a predefined list of IPs and an optional error.
type fakeResolver struct {
	results []net.IP
	err     error
}

func (f *fakeResolver) LookupIP(_ context.Context, _ string, _ string) ([]net.IP, error) {
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
		result := resolver.Resolve(
			context.Background(), time.Second, 1, v1alpha1.Ipv4, []v1alpha1.FQDN{"example.com"},
		)

		assert.Len(t, result, 1)
		require.NoError(t, result[0].Error)
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
		result := resolver.Resolve(
			context.Background(), time.Second, 1, v1alpha1.All, []v1alpha1.FQDN{invalidFQDN},
		)

		assert.Len(t, result, 1)
		require.Error(t, result[0].Error)
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
		result := resolver.Resolve(
			context.Background(), 100*time.Millisecond, 1, v1alpha1.All, []v1alpha1.FQDN{"timeout.com"},
		)
		elapsed := time.Since(start)

		assert.Less(t, elapsed, 500*time.Millisecond, "Should timeout early")
		assert.Len(t, result, 1)
		require.Error(t, result[0].Error)
		assert.True(t, errors.Is(result[0].Error, context.DeadlineExceeded))
	})
}

func TestDNSResolver_ResolveGoogle(t *testing.T) {
	resolver := NewDNSResolver()
	result := resolver.Resolve(
		context.Background(), time.Second*3, 1, v1alpha1.Ipv4, []v1alpha1.FQDN{"google.com"},
	)
	t.Log(result.CIDRs())
}
