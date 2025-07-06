package controller

import (
	"github.com/konsole-is/fqdn-controller/api/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	netv1 "k8s.io/api/networking/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
)

var _ = Describe("NetworkPolicyReconciler", func() {
	Context("when calling reconcileNetworkPolicyDeletion", func() {
		var (
			reconciler    *NetworkPolicyReconciler
			np            *v1alpha1.NetworkPolicy
			networkPolicy *netv1.NetworkPolicy
		)

		BeforeEach(func() {
			np = &v1alpha1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-delete-policy",
					Namespace: "default",
				},
			}
			Expect(k8sClient.Create(ctx, np)).To(Succeed())

			reconciler = &NetworkPolicyReconciler{
				Client:        k8sClient,
				Scheme:        k8sClient.Scheme(),
				EventRecorder: record.NewFakeRecorder(10),
			}
		})

		AfterEach(func() {
			Expect(k8sClient.Delete(ctx, np)).To(Succeed())
		})

		It("should successfully delete the network policy and emit event", func() {
			networkPolicy = &netv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      np.Name,
					Namespace: np.Namespace,
				},
			}
			Expect(k8sClient.Create(ctx, networkPolicy)).To(Succeed())

			// Sanity check
			found := &netv1.NetworkPolicy{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: np.Name, Namespace: np.Namespace}, found)).To(Succeed())

			// Perform deletion
			err := reconciler.reconcileNetworkPolicyDeletion(ctx, np)
			Expect(err).NotTo(HaveOccurred())

			// Verify deletion
			err = k8sClient.Get(ctx, types.NamespacedName{Name: np.Name, Namespace: np.Namespace}, found)
			Expect(k8serrors.IsNotFound(err)).To(BeTrue())
		})

		It("should not return error if the network policy does not exist", func() {
			// Do not create the network policy
			err := reconciler.reconcileNetworkPolicyDeletion(ctx, np)
			Expect(err).NotTo(HaveOccurred())
		})
	})
})
