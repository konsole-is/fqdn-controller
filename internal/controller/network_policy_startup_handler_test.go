package controller

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/konsole-is/fqdn-controller/api/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type fakeManager struct {
	electedCh chan struct{}
}

func (f fakeManager) Elected() <-chan struct{} {
	return f.electedCh
}

var _ = Describe("NetworkPolicyStartupHandler", func() {
	Context("when calling queueAllNetworkPolicies", func() {
		var (
			startupTime        time.Time
			expectedLabelValue string
		)

		BeforeEach(func() {
			startupTime = time.Now()
			expectedLabelValue = fmt.Sprintf("%d", startupTime.UnixMilli())
		})

		AfterEach(func() {})

		It("should annotate all NetworkPolicy resources missing the startup annotation", func() {
			np1 := &v1alpha1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "np-without-annotation",
					Namespace: "default",
				},
				Spec: v1alpha1.NetworkPolicySpec{},
			}
			np2 := &v1alpha1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "np-with-annotation",
					Namespace: "default",
					Annotations: map[string]string{
						startupAnnotationKey: expectedLabelValue,
					},
				},
				Spec: v1alpha1.NetworkPolicySpec{},
			}

			Expect(k8sClient.Create(ctx, np1)).To(Succeed())
			Expect(k8sClient.Create(ctx, np2)).To(Succeed())

			DeferCleanup(func() {
				Expect(k8sClient.Delete(ctx, np1)).To(Succeed())
				Expect(k8sClient.Delete(ctx, np2)).To(Succeed())
			})

			Expect(queueAllNetworkPolicies(ctx, k8sClient, startupTime)).To(Succeed())

			// np1 should now have the annotation set
			var updatedNP1 v1alpha1.NetworkPolicy
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: np1.Name, Namespace: np1.Namespace}, &updatedNP1)).To(Succeed())
			Expect(updatedNP1.Annotations).To(HaveKeyWithValue(startupAnnotationKey, expectedLabelValue))

			// np2 should remain unchanged
			var updatedNP2 v1alpha1.NetworkPolicy
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: np2.Name, Namespace: np2.Namespace}, &updatedNP2)).To(Succeed())
			Expect(updatedNP2.Annotations[startupAnnotationKey]).To(Equal(expectedLabelValue))
		})
	})
	Context("when calling queueExistingPoliciesOnLeaderElection", func() {
		var (
			reconciler *NetworkPolicyReconciler
			fakeMgr    *fakeManager
			calls      int
			mu         sync.Mutex
		)

		BeforeEach(func() {
			reconciler = &NetworkPolicyReconciler{}
			calls = 0
			policyQueuer = func(ctx context.Context, cli client.Client, t time.Time) error {
				mu.Lock()
				defer mu.Unlock()
				calls++
				if calls < 2 {
					return errors.New("simulated failure")
				}
				return nil
			}
			// Speed up retries in test
			sleepFn = func(d time.Duration) {
				time.Sleep(10 * time.Millisecond)
			}

			fakeMgr = &fakeManager{
				electedCh: make(chan struct{}),
			}
		})
		AfterEach(func() {
			sleepFn = time.Sleep
		})

		It("should retry until queueAllNetworkPolicies succeeds", func() {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			go reconciler.queueExistingPoliciesOnLeaderElection(ctx, fakeMgr)

			// Simulate leader election
			close(fakeMgr.electedCh)

			Eventually(func() int {
				mu.Lock()
				defer mu.Unlock()
				return calls
			}).Should(BeNumerically(">=", 2))
		})

		It("should exit if context is canceled before leader election", func() {
			ctx, cancel := context.WithCancel(context.Background())

			// Start the reconciler
			go reconciler.queueExistingPoliciesOnLeaderElection(ctx, fakeMgr)

			// Cancel the context before election
			cancel()

			// Wait briefly to ensure it exits without panicking
			Consistently(func() int {
				mu.Lock()
				defer mu.Unlock()
				return calls
			}).Should(Equal(0))
		})
	})
})
