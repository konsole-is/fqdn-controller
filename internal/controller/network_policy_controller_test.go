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
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"time"

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

		dnsResolver := &network.FakeDNSResolver{}
		dnsResolver.SetResults([]*network.DNSResolverResult{
			{
				Domain: "example.com",
				Error:  nil,
				CIDRs: []*v1alpha1.CIDR{
					v1alpha1.MustCIDR("0.0.0.0/0"),
				},
			},
			{
				Domain: "google.com",
				Error:  nil,
				CIDRs: []*v1alpha1.CIDR{
					v1alpha1.MustCIDR("192.168.0.0/32"),
				},
			},
		})

		BeforeEach(func() {
			By("creating the custom resource for the Kind NetworkPolicy")
			err := k8sClient.Get(ctx, typeNamespacedName, np)
			if err != nil && errors.IsNotFound(err) {
				resource := &v1alpha1.NetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      resourceName,
						Namespace: "default",
					},
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
		})

		AfterEach(func() {
			resource := &v1alpha1.NetworkPolicy{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			Expect(err).NotTo(HaveOccurred())

			By("Cleanup the specific resource instance NetworkPolicy")
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
		})

		It("should successfully reconcile the resource", func() {
			By("Reconciling the created resource")
			controllerReconciler := &NetworkPolicyReconciler{
				Client:        k8sClient,
				Scheme:        k8sClient.Scheme(),
				EventRecorder: record.NewFakeRecorder(10),
				DNSResolver:   dnsResolver,
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
			Expect(np.Status.LatestErrors).Should(BeEmpty())
			Expect(np.Status.LatestLookupTime).ToNot(BeZero())
			Expect(np.Status.AppliedAddressCount).To(Equal(int32(2)))
			Expect(np.Status.BlockedAddressCount).To(Equal(int32(0)))
			Expect(np.Status.ResolvedAddresses).To(Equal(map[v1alpha1.FQDN][]string{
				"example.com": {"0.0.0.0/0"},
				"google.com":  {"192.168.0.0/32"},
			}))

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
	})
})
