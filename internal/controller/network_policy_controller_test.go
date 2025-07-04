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
	"fmt"
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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/konsole-is/fqdn-controller/api/v1alpha1"
)

var _ = Describe("NetworkPolicy Controller", func() {
	Context("When reconciling a resource", func() {
		const resourceName = "test-resource"

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: "default",
		}
		np := &v1alpha1.NetworkPolicy{}

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
						v1alpha1.MustCIDR("192.168.0.0/24"),
					},
				},
			})
			controllerReconciler := &NetworkPolicyReconciler{
				Client:        k8sClient,
				Scheme:        k8sClient.Scheme(),
				EventRecorder: record.NewFakeRecorder(10),
				DNSResolver:   dnsResolver,
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			np := &v1alpha1.NetworkPolicy{}
			err = k8sClient.Get(ctx, typeNamespacedName, np)
			Expect(err).NotTo(HaveOccurred())
			t := GinkgoT()

			networkPolicy := &netv1.NetworkPolicy{}
			err = k8sClient.Get(ctx, typeNamespacedName, networkPolicy)
			Expect(err).NotTo(HaveOccurred())
			t.Log(fmt.Sprintf("%+v", networkPolicy))

			cond := meta.FindStatusCondition(np.Status.Conditions, string(v1alpha1.NetworkPolicyReadyCondition))
			t.Log(cond)
			t.Log(fmt.Sprintf("%+v", np.Status))
			Expect(cond).ToNot(BeNil())
			Expect(string(cond.Status)).To(Equal(string(corev1.ConditionTrue)))
			Expect(np.Status.ObservedGeneration).To(BeZero()) // first edit is gen 0
			Expect(np.Status.LatestErrors).Should(BeEmpty())
			Expect(np.Status.LatestLookupTime).ToNot(BeZero())
			Expect(np.Status.CurrentAddressCount).To(Equal(2))
			Expect(np.Status.BlockedAddressCount).To(Equal(0))
			Expect(np.Status.ResolvedAddresses).To(Equal(map[v1alpha1.FQDN]string{
				"example.com": "0.0.0.0/0",
				"google.com":  "192.168.12.2/32",
			}))
		})
	})
})
