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

package controller

import (
	"context"
	"net"
	"time"

	"github.com/konsole-is/fqdn-controller/pkg/network"
	testutils "github.com/konsole-is/fqdn-controller/test/utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/konsole-is/fqdn-controller/api/v1alpha1"
)

var _ = Describe("NetworkPolicy Controller", func() {
	Context("When reconciling a resource", func() {
		const resourceName = "test-resource"

		ctx := context.Background()
		np := &v1alpha1.NetworkPolicy{}

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: "default",
		}
		objectMeta := metav1.ObjectMeta{
			Name:      typeNamespacedName.Name,
			Namespace: typeNamespacedName.Namespace,
		}

		dnsResolver := &network.FakeDNSResolver{
			Results: []*network.DNSResolverResult{
				{
					Domain:  "example.com",
					Error:   nil,
					Status:  v1alpha1.NetworkPolicyResolveSuccess,
					Message: "Success test example",
					CIDRs: []*v1alpha1.CIDR{
						v1alpha1.MustCIDR("0.0.0.0/0"),
					},
				},
				{
					Domain:  "google.com",
					Error:   nil,
					Status:  v1alpha1.NetworkPolicyResolveSuccess,
					Message: "Success test google",
					CIDRs: []*v1alpha1.CIDR{
						v1alpha1.MustCIDR("192.168.0.0/32"),
					},
				},
			},
		}

		AfterEach(func() {
			resource := &v1alpha1.NetworkPolicy{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			Expect(err).NotTo(HaveOccurred())

			By("Cleanup the specific resource instance NetworkPolicy")
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
		})

		It("should successfully reconcile the resource", func() {
			By("creating the custom resource for the Kind NetworkPolicy")
			err := k8sClient.Get(ctx, typeNamespacedName, np)
			if err != nil && errors.IsNotFound(err) {
				resource := &v1alpha1.NetworkPolicy{
					ObjectMeta: objectMeta,
					Spec: v1alpha1.NetworkPolicySpec{
						ResolveTimeoutSeconds: 5,
						TTLSeconds:            180,
						BlockPrivateIPs:       false,
						EnabledNetworkType:    v1alpha1.All,
						PodSelector:           testutils.PodSelector("foo", "bar"),
						Ingress: []v1alpha1.IngressRule{
							testutils.TCPIngressRule([]v1alpha1.FQDN{"example.com"}, []int{80, 443}),
						},
						Egress: []v1alpha1.EgressRule{
							testutils.TCPEgressRule([]v1alpha1.FQDN{"google.com"}, []int{80, 443}),
						},
					},
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
			By("Reconciling the created resource")
			controllerReconciler := &NetworkPolicyReconciler{
				Client:                k8sClient,
				Scheme:                k8sClient.Scheme(),
				EventRecorder:         record.NewFakeRecorder(10),
				DNSResolver:           dnsResolver,
				MaxConcurrentResolves: 4,
			}

			result, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			np := &v1alpha1.NetworkPolicy{}
			err = k8sClient.Get(ctx, typeNamespacedName, np)
			Expect(err).NotTo(HaveOccurred())

			t := GinkgoT()
			By("Validating the ready status condition")
			cond := meta.FindStatusCondition(np.Status.Conditions, string(v1alpha1.NetworkPolicyReadyCondition))
			Expect(cond).ToNot(BeNil())
			t.Log(testutils.PrettyForPrint(cond))
			Expect(string(cond.Status)).To(Equal(string(corev1.ConditionTrue)))
			Expect(cond.Reason).To(Equal(string(v1alpha1.NetworkPolicyReady)))

			By("Validating the resolve status condition")
			cond = meta.FindStatusCondition(np.Status.Conditions, string(v1alpha1.NetworkPolicyResolveCondition))
			Expect(cond).ToNot(BeNil())
			t.Log(testutils.PrettyForPrint(cond))
			Expect(string(cond.Status)).To(Equal(string(corev1.ConditionTrue)))
			Expect(cond.Reason).To(Equal(string(v1alpha1.NetworkPolicyResolveSuccess)))

			By("Validating the status fields")
			t.Log(testutils.PrettyForPrint(np.Status))
			Expect(np.Status.ObservedGeneration).To(Equal(int64(1))) // first successful reconcile -> gen 1
			Expect(np.Status.LatestLookupTime).ToNot(BeZero())
			Expect(np.Status.TotalAddressCount).To(Equal(int32(2)))
			Expect(np.Status.AppliedAddressCount).To(Equal(int32(2)))
			Expect(np.Status.FQDNs).To(HaveLen(2))
			lookup := v1alpha1.FQDNStatusList(np.Status.FQDNs).LookupTable()
			Expect(lookup["google.com"].ResolveReason).To(Equal(v1alpha1.NetworkPolicyResolveSuccess))
			Expect(lookup["google.com"].ResolveMessage).To(Equal("Success test google"))
			Expect(lookup["google.com"].Addresses).To(Equal([]string{"192.168.0.0/32"}))
			Expect(lookup["google.com"].LastSuccessfulTime).ToNot(BeZero())
			Expect(lookup["google.com"].LastTransitionTime).ToNot(BeZero())
			Expect(lookup["example.com"].ResolveReason).To(Equal(v1alpha1.NetworkPolicyResolveSuccess))
			Expect(lookup["example.com"].ResolveMessage).To(Equal("Success test example"))
			Expect(lookup["example.com"].Addresses).To(Equal([]string{"0.0.0.0/0"}))
			Expect(lookup["example.com"].LastSuccessfulTime).ToNot(BeZero())
			Expect(lookup["example.com"].LastTransitionTime).ToNot(BeZero())

			By("Ensuring a requeue was set to TTL")
			Expect(result.RequeueAfter).To(Equal(time.Duration(np.Spec.TTLSeconds) * time.Second))

			By("Ensuring the underlying network policy was created")
			networkPolicy := &netv1.NetworkPolicy{}
			err = k8sClient.Get(ctx, typeNamespacedName, networkPolicy)
			Expect(err).NotTo(HaveOccurred())
			t.Log(testutils.PrettyForPrint(networkPolicy))

			By("Ensuring the underlying network policy has the correct pod selector")
			Expect(networkPolicy.Spec.PodSelector).To(Equal(testutils.PodSelector("foo", "bar")))

			By("Ensuring the underlying network policy has the correct ingress rules")
			Expect(networkPolicy.Spec.Ingress).To(HaveLen(1))
			Expect(networkPolicy.Spec.Ingress[0]).To(Equal(netv1.NetworkPolicyIngressRule{
				Ports: []netv1.NetworkPolicyPort{
					testutils.TCPNetworkPolicyPort(80, 80),
					testutils.TCPNetworkPolicyPort(443, 443),
				},
				From: []netv1.NetworkPolicyPeer{
					{
						IPBlock: &netv1.IPBlock{
							CIDR: "0.0.0.0/0",
						},
					},
				},
			}))
			By("Ensuring the underlying network policy has the correct egress rules")
			Expect(networkPolicy.Spec.Egress).To(HaveLen(1))
			Expect(networkPolicy.Spec.Egress[0]).To(Equal(netv1.NetworkPolicyEgressRule{
				Ports: []netv1.NetworkPolicyPort{
					testutils.TCPNetworkPolicyPort(80, 80),
					testutils.TCPNetworkPolicyPort(443, 443),
				},
				To: []netv1.NetworkPolicyPeer{
					{
						IPBlock: &netv1.IPBlock{
							CIDR: "192.168.0.0/32",
						},
					},
				},
			}))
		})

		It("should default specific fields when not set", func() {
			By("Creating a resource with unspecified fields")
			resource := &v1alpha1.NetworkPolicy{
				ObjectMeta: objectMeta,
				Spec: v1alpha1.NetworkPolicySpec{
					// ResolveTimeoutSeconds: 3,
					// TTLSeconds:            300,
					// RetryTimeoutSeconds: ptr.To(3600),
					// BlockPrivateIPs:    false,
					// EnabledNetworkType: v1alpha1.All,
					PodSelector: testutils.PodSelector("foo", "bar"),
					Ingress: []v1alpha1.IngressRule{
						testutils.TCPIngressRule([]v1alpha1.FQDN{"example.com"}, []int{80}),
					},
				},
			}
			Expect(k8sClient.Create(ctx, resource)).To(Succeed())

			By("Reconciling the resource")
			controllerReconciler := &NetworkPolicyReconciler{
				Client:                k8sClient,
				Scheme:                k8sClient.Scheme(),
				EventRecorder:         record.NewFakeRecorder(10),
				MaxConcurrentResolves: 4,
				DNSResolver: &network.FakeDNSResolver{
					Results: []*network.DNSResolverResult{
						{
							Domain:  "example.com",
							Error:   nil,
							Status:  v1alpha1.NetworkPolicyResolveSuccess,
							Message: "resolved",
							CIDRs: []*v1alpha1.CIDR{
								v1alpha1.MustCIDR("1.2.3.4/32"),
							},
						},
					},
				},
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: typeNamespacedName})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying defaults are applied as specified")
			updated := &v1alpha1.NetworkPolicy{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updated)).To(Succeed())
			Expect(*updated.Spec.RetryTimeoutSeconds).To(Equal(int32(3600)))
			Expect(updated.Spec.BlockPrivateIPs).To(BeFalse())
			Expect(updated.Spec.TTLSeconds).To(Equal(int32(300)))
			Expect(updated.Spec.ResolveTimeoutSeconds).To(Equal(int32(3)))
			Expect(updated.Spec.EnabledNetworkType).To(Equal(v1alpha1.Ipv4))
			Expect(updated.Status.FQDNs).To(HaveLen(1))
		})
	})

	Context("when reconciling a resource after previously successful dns resolves", func() {
		const resourceName = "test-resolve-error-resource"

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: "default",
		}
		objectMeta := metav1.ObjectMeta{
			Name:      typeNamespacedName.Name,
			Namespace: typeNamespacedName.Namespace,
		}
		initialDNSResolver := &network.FakeDNSResolver{
			Results: []*network.DNSResolverResult{
				{
					Domain:  "example.com",
					Error:   nil,
					Status:  v1alpha1.NetworkPolicyResolveSuccess,
					Message: "initial success",
					CIDRs: []*v1alpha1.CIDR{
						v1alpha1.MustCIDR("5.6.7.8/32"),
					},
				},
			},
		}
		var controllerReconciler *NetworkPolicyReconciler

		BeforeEach(func() {
			By("Creating a resource with a successful resolution first")
			resource := &v1alpha1.NetworkPolicy{
				ObjectMeta: objectMeta,
				Spec: v1alpha1.NetworkPolicySpec{
					ResolveTimeoutSeconds: 5,
					RetryTimeoutSeconds:   ptr.To(int32(3600)), // long timeout, but irrelevant for non-transient
					TTLSeconds:            180,
					BlockPrivateIPs:       false,
					EnabledNetworkType:    v1alpha1.All,
					PodSelector:           testutils.PodSelector("foo", "bar"),
					Ingress: []v1alpha1.IngressRule{
						testutils.TCPIngressRule([]v1alpha1.FQDN{"example.com"}, []int{80}),
					},
				},
			}
			Expect(k8sClient.Create(ctx, resource)).To(Succeed())

			controllerReconciler = &NetworkPolicyReconciler{
				Client:                k8sClient,
				Scheme:                k8sClient.Scheme(),
				EventRecorder:         record.NewFakeRecorder(10),
				DNSResolver:           initialDNSResolver,
				MaxConcurrentResolves: 4,
			}
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: typeNamespacedName})
			Expect(err).NotTo(HaveOccurred())
			By("Verifying initial status shows resolved address")
			np := &v1alpha1.NetworkPolicy{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, np)).To(Succeed())
			lookup := v1alpha1.FQDNStatusList(np.Status.FQDNs).LookupTable()
			Expect(lookup["example.com"].Addresses).To(Equal([]string{"5.6.7.8/32"}))
			Expect(lookup["example.com"].ResolveReason).To(Equal(v1alpha1.NetworkPolicyResolveSuccess))

			// Underlying network policy should be created
			networkPolicy := &netv1.NetworkPolicy{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, networkPolicy)).To(Succeed())

		})

		AfterEach(func() {
			np := &v1alpha1.NetworkPolicy{}
			err := k8sClient.Get(ctx, typeNamespacedName, np)
			Expect(err).NotTo(HaveOccurred())

			By("Validating that the resolve status is failed")
			// Ready condition should be set to not ready
			cond := meta.FindStatusCondition(np.Status.Conditions, string(v1alpha1.NetworkPolicyResolveCondition))
			Expect(cond).ToNot(BeNil())
			Expect(cond.Status).To(Equal(metav1.ConditionFalse))
			Expect(cond.Reason).ToNot(Equal(string(v1alpha1.NetworkPolicyResolveSuccess)))

			By("Cleanup the specific resource instance NetworkPolicy")
			Expect(k8sClient.Delete(ctx, np)).To(Succeed())
		})

		It("should not clear addresses on transient error before retry timeout", func() {
			np := &v1alpha1.NetworkPolicy{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, np)).To(Succeed())
			initialStatus := v1alpha1.FQDNStatusList(np.Status.FQDNs).LookupTable()["example.com"]
			Expect(initialStatus.ResolveReason).To(Equal(v1alpha1.NetworkPolicyResolveSuccess)) // updated reason
			Expect(initialStatus.Addresses).To(Equal([]string{"5.6.7.8/32"}))

			By("Triggering a transient failure before retry timeout")
			transientDNSResolver := &network.FakeDNSResolver{
				Results: []*network.DNSResolverResult{
					{
						Domain: "example.com",
						Error: &net.DNSError{
							IsTemporary: true,
						},
						Status:  v1alpha1.NetworkPolicyResolveTemporaryError, // Transient
						Message: "transient",
						CIDRs:   []*v1alpha1.CIDR{},
					},
				},
			}
			controllerReconciler.DNSResolver = transientDNSResolver
			time.Sleep(time.Second) // sleep to ensure new time on LastTransitionTime
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: typeNamespacedName})
			Expect(err).NotTo(HaveOccurred())

			By("Validating that addresses are retained")
			updated := &v1alpha1.NetworkPolicy{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updated)).To(Succeed())

			Expect(updated.Status.FQDNs).To(HaveLen(1))
			status := v1alpha1.FQDNStatusList(updated.Status.FQDNs).LookupTable()["example.com"]
			Expect(status.ResolveReason).To(Equal(v1alpha1.NetworkPolicyResolveTemporaryError)) // updated reason
			Expect(status.Addresses).To(Equal([]string{"5.6.7.8/32"}))                          // still retained
			Expect(status.LastTransitionTime).ToNot(Equal(initialStatus.LastTransitionTime))
			Expect(status.LastSuccessfulTime).To(Equal(initialStatus.LastSuccessfulTime))
		})

		It("should clear addresses on transient error after retry timeout", func() {
			By("Updating the RetryTimeoutSeconds value to 2 seconds")
			np := &v1alpha1.NetworkPolicy{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, np)).To(Succeed())
			np.Spec.RetryTimeoutSeconds = ptr.To(int32(2))
			Expect(k8sClient.Update(ctx, np)).To(Succeed())

			By("Triggering a transient failure after retry timeout")
			time.Sleep(3 * time.Second) // wait to exceed retry timeout
			transientDNSResolver := &network.FakeDNSResolver{
				Results: []*network.DNSResolverResult{
					{
						Domain: "example.com",
						Error: &net.DNSError{
							IsTemporary: true,
						},
						Status:  v1alpha1.NetworkPolicyResolveTemporaryError,
						Message: "transient failure",
						CIDRs:   []*v1alpha1.CIDR{},
					},
				},
			}
			controllerReconciler.DNSResolver = transientDNSResolver
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: typeNamespacedName})
			Expect(err).NotTo(HaveOccurred())

			By("Validating that addresses have been cleared")
			updated := &v1alpha1.NetworkPolicy{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updated)).To(Succeed())

			Expect(updated.Status.FQDNs).To(HaveLen(1))
			status := v1alpha1.FQDNStatusList(updated.Status.FQDNs).LookupTable()["example.com"]
			Expect(status.ResolveReason).To(Equal(v1alpha1.NetworkPolicyResolveTemporaryError))
			Expect(status.Addresses).To(BeEmpty())            // cleared due to retry timeout
			Expect(status.LastSuccessfulTime).ToNot(BeZero()) // kept intact
			Expect(status.LastTransitionTime).ToNot(BeZero())
		})

		It("should clear addresses immediately on non-transient error", func() {
			By("Triggering a non-transient failure (e.g., NXDOMAIN)")
			nonTransientDNSResolver := &network.FakeDNSResolver{
				Results: []*network.DNSResolverResult{
					{
						Domain: "example.com",
						Error: &net.DNSError{
							IsNotFound: true,
						},
						Status:  v1alpha1.NetworkPolicyResolveDomainNotFound, // Non-transient
						Message: "non-transient error: NXDOMAIN",
						CIDRs:   []*v1alpha1.CIDR{},
					},
				},
			}
			controllerReconciler.DNSResolver = nonTransientDNSResolver
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: typeNamespacedName})
			Expect(err).NotTo(HaveOccurred())

			By("Validating that addresses have been cleared immediately")
			updated := &v1alpha1.NetworkPolicy{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updated)).To(Succeed())

			Expect(updated.Status.FQDNs).To(HaveLen(1))
			status := v1alpha1.FQDNStatusList(updated.Status.FQDNs).LookupTable()["example.com"]
			Expect(status.ResolveReason).To(Equal(v1alpha1.NetworkPolicyResolveDomainNotFound))
			Expect(status.ResolveMessage).To(ContainSubstring("non-transient"))
			Expect(status.Addresses).To(BeEmpty())            // cleared immediately
			Expect(status.LastSuccessfulTime).ToNot(BeZero()) // preserved from success
			Expect(status.LastTransitionTime).ToNot(BeZero())
		})

		It("should become not ready and delete network policy when all addresses are cleared", func() {
			By("Updating the RetryTimeoutSeconds value to 0 seconds")
			np := &v1alpha1.NetworkPolicy{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, np)).To(Succeed())
			np.Spec.RetryTimeoutSeconds = ptr.To(int32(0))
			Expect(k8sClient.Update(ctx, np)).To(Succeed())

			By("Reconciling again with an error response that clears addresses")
			errorDNSResolver := &network.FakeDNSResolver{
				Results: []*network.DNSResolverResult{
					{
						Domain: "example.com",
						Error: &net.DNSError{
							IsTemporary: true,
						},
						Status:  v1alpha1.NetworkPolicyResolveTemporaryError,
						Message: "simulated transient failure",
						CIDRs:   []*v1alpha1.CIDR{},
					},
				},
			}
			controllerReconciler.DNSResolver = errorDNSResolver
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: typeNamespacedName})
			Expect(err).NotTo(HaveOccurred())

			By("Validating status has no addresses and is marked not ready")
			updated := &v1alpha1.NetworkPolicy{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updated)).To(Succeed())

			// FQDNs should be present but cleared
			Expect(updated.Status.FQDNs).To(HaveLen(1))
			updatedLookup := v1alpha1.FQDNStatusList(updated.Status.FQDNs).LookupTable()
			Expect(updatedLookup["example.com"].Addresses).To(BeEmpty())
			Expect(updatedLookup["example.com"].ResolveReason).To(Equal(v1alpha1.NetworkPolicyResolveTemporaryError))

			// Ready condition should be set to not ready
			cond := meta.FindStatusCondition(updated.Status.Conditions, string(v1alpha1.NetworkPolicyReadyCondition))
			Expect(cond).ToNot(BeNil())
			Expect(cond.Status).To(Equal(metav1.ConditionFalse))
			Expect(cond.Reason).To(Equal(string(v1alpha1.NetworkPolicyEmptyRules)))

			By("Validating the underlying netv1.NetworkPolicy is deleted")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, typeNamespacedName, &netv1.NetworkPolicy{})
				return errors.IsNotFound(err)
			}, 5*time.Second, 250*time.Millisecond).Should(BeTrue())
		})
	})

	Context("when reconciling a resource from an unready state", func() {
		const resourceName = "test-resolve-unready-resource"

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: "default",
		}
		objectMeta := metav1.ObjectMeta{
			Name:      typeNamespacedName.Name,
			Namespace: typeNamespacedName.Namespace,
		}
		initialDNSResolver := &network.FakeDNSResolver{
			Results: []*network.DNSResolverResult{
				{
					Domain: "example.com",
					Error: &net.DNSError{
						IsNotFound: true,
					},
					Status:  v1alpha1.NetworkPolicyResolveDomainNotFound,
					Message: "initial failure",
					CIDRs:   []*v1alpha1.CIDR{},
				},
			},
		}
		var controllerReconciler *NetworkPolicyReconciler

		BeforeEach(func() {
			By("Creating a resource with a failed resolution first")
			resource := &v1alpha1.NetworkPolicy{
				ObjectMeta: objectMeta,
				Spec: v1alpha1.NetworkPolicySpec{
					ResolveTimeoutSeconds: 5,
					RetryTimeoutSeconds:   ptr.To(int32(3600)),
					TTLSeconds:            180,
					BlockPrivateIPs:       false,
					EnabledNetworkType:    v1alpha1.All,
					PodSelector:           testutils.PodSelector("foo", "bar"),
					Ingress: []v1alpha1.IngressRule{
						testutils.TCPIngressRule([]v1alpha1.FQDN{"example.com"}, []int{80}),
					},
				},
			}
			Expect(k8sClient.Create(ctx, resource)).To(Succeed())

			controllerReconciler = &NetworkPolicyReconciler{
				Client:                k8sClient,
				Scheme:                k8sClient.Scheme(),
				EventRecorder:         record.NewFakeRecorder(10),
				DNSResolver:           initialDNSResolver,
				MaxConcurrentResolves: 4,
			}
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: typeNamespacedName})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying initial condition is not ready")
			np := &v1alpha1.NetworkPolicy{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, np)).To(Succeed())
			cond := meta.FindStatusCondition(np.Status.Conditions, string(v1alpha1.NetworkPolicyReadyCondition))
			Expect(cond).ToNot(BeNil())
			Expect(cond.Status).To(Equal(metav1.ConditionFalse))
			Expect(cond.Reason).To(Equal(string(v1alpha1.NetworkPolicyEmptyRules)))
			lookup := v1alpha1.FQDNStatusList(np.Status.FQDNs).LookupTable()
			Expect(lookup["example.com"].Addresses).To(BeEmpty())
			Expect(lookup["example.com"].ResolveReason).To(Equal(v1alpha1.NetworkPolicyResolveDomainNotFound))

			By("Verifying underlying network policy is not created")
			networkPolicy := &netv1.NetworkPolicy{}
			err = k8sClient.Get(ctx, typeNamespacedName, networkPolicy)
			Expect(errors.IsNotFound(err)).To(BeTrue())
		})

		AfterEach(func() {
			np := &v1alpha1.NetworkPolicy{}
			err := k8sClient.Get(ctx, typeNamespacedName, np)
			Expect(err).NotTo(HaveOccurred())

			By("Cleanup the specific resource instance NetworkPolicy")
			Expect(k8sClient.Delete(ctx, np)).To(Succeed())
		})

		It("should become ready once any addresses are available", func() {
			By("Switching DNS resolver to return a valid result")
			successDNSResolver := &network.FakeDNSResolver{
				Results: []*network.DNSResolverResult{
					{
						Domain:  "example.com",
						Error:   nil,
						Status:  v1alpha1.NetworkPolicyResolveSuccess,
						Message: "recovered resolution",
						CIDRs: []*v1alpha1.CIDR{
							v1alpha1.MustCIDR("1.1.1.1/32"),
						},
					},
				},
			}
			controllerReconciler.DNSResolver = successDNSResolver

			By("Reconciling again with successful resolution")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: typeNamespacedName})
			Expect(err).NotTo(HaveOccurred())

			np := &v1alpha1.NetworkPolicy{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, np)).To(Succeed())

			By("Verifying ready condition is true and addresses are applied")
			cond := meta.FindStatusCondition(np.Status.Conditions, string(v1alpha1.NetworkPolicyReadyCondition))
			Expect(cond).ToNot(BeNil())
			Expect(cond.Status).To(Equal(metav1.ConditionTrue))
			Expect(cond.Reason).To(Equal(string(v1alpha1.NetworkPolicyReady)))

			resolveCond := meta.FindStatusCondition(np.Status.Conditions, string(v1alpha1.NetworkPolicyResolveCondition))
			Expect(resolveCond).ToNot(BeNil())
			Expect(resolveCond.Status).To(Equal(metav1.ConditionTrue))
			Expect(resolveCond.Reason).To(Equal(string(v1alpha1.NetworkPolicyResolveSuccess)))

			lookup := v1alpha1.FQDNStatusList(np.Status.FQDNs).LookupTable()
			Expect(lookup["example.com"].Addresses).To(Equal([]string{"1.1.1.1/32"}))
			Expect(lookup["example.com"].ResolveReason).To(Equal(v1alpha1.NetworkPolicyResolveSuccess))

			By("Validating the underlying network policy is now created")
			networkPolicy := &netv1.NetworkPolicy{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, networkPolicy)).To(Succeed())
			Expect(networkPolicy.Spec.PodSelector).To(Equal(testutils.PodSelector("foo", "bar")))
			Expect(networkPolicy.Spec.Ingress).To(HaveLen(1))
			Expect(networkPolicy.Spec.Ingress[0].From).To(ContainElement(
				netv1.NetworkPolicyPeer{
					IPBlock: &netv1.IPBlock{
						CIDR: "1.1.1.1/32",
					},
				}),
			)
		})
	})
})
