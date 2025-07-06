package controller

import (
	"github.com/konsole-is/fqdn-controller/api/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
)

var _ = Describe("NetworkPolicyReconciler", func() {
	Context("when calling reconcileNetworkPolicyCreation", func() {
		var (
			reconciler    *NetworkPolicyReconciler
			np            *v1alpha1.NetworkPolicy
			networkPolicy *netv1.NetworkPolicy
		)

		BeforeEach(func() {
			np = &v1alpha1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
			}

			networkPolicy = &netv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      np.Name,
					Namespace: np.Namespace,
					Labels: map[string]string{
						"app": "test",
					},
					Annotations: map[string]string{
						"note": "created by test",
					},
				},
				Spec: netv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"role": "db",
						},
					},
					PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
				},
			}

			reconciler = &NetworkPolicyReconciler{
				Client:        k8sClient,
				Scheme:        k8sClient.Scheme(),
				EventRecorder: record.NewFakeRecorder(10),
			}

			// Create the parent NetworkPolicy so the controller reference works
			Expect(k8sClient.Create(ctx, np)).To(Succeed())
		})

		AfterEach(func() {
			Expect(k8sClient.Delete(ctx, np)).To(Succeed())
		})

		It("should create the network policy and set controller reference", func() {
			err := reconciler.reconcileNetworkPolicyCreation(ctx, np, networkPolicy)
			Expect(err).NotTo(HaveOccurred())

			current := &netv1.NetworkPolicy{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: np.Name, Namespace: np.Namespace}, current)).To(Succeed())

			Expect(current.Labels).To(Equal(networkPolicy.Labels))
			Expect(current.Annotations).To(Equal(networkPolicy.Annotations))
			Expect(current.Spec.PodSelector.MatchLabels).To(Equal(networkPolicy.Spec.PodSelector.MatchLabels))
			Expect(current.Spec.PolicyTypes).To(Equal(networkPolicy.Spec.PolicyTypes))

			// Confirm the owner reference is set correctly
			Expect(current.OwnerReferences).To(HaveLen(1))
			Expect(current.OwnerReferences[0].Kind).To(Equal("NetworkPolicy"))
			Expect(current.OwnerReferences[0].Name).To(Equal(np.Name))
		})
	})
})
