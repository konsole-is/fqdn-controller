package controller

import (
	"context"
	"github.com/konsole-is/fqdn-controller/api/v1alpha1"
	"github.com/konsole-is/fqdn-controller/pkg/utils"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// reconcileNetworkPolicyCreation Removes the underlying network policy
func (r *NetworkPolicyReconciler) reconcileNetworkPolicyDeletion(ctx context.Context, np *v1alpha1.NetworkPolicy) error {
	networkPolicy := &netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      np.Name,
			Namespace: np.Namespace,
		},
	}
	if err := r.Client.Delete(ctx, networkPolicy); err != nil && !errors.IsNotFound(err) {
		return err
	}
	r.EventRecorder.Event(
		np, corev1.EventTypeNormal,
		utils.DeletionReason(networkPolicy), utils.DeletionMessage(networkPolicy),
	)
	return nil
}
