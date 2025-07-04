package controller

import (
	"context"
	"github.com/konsole-is/fqdn-controller/api/v1alpha1"
	"github.com/konsole-is/fqdn-controller/pkg/utils"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// reconcileNetworkPolicyCreation Creates the underlying network policy
func (r *NetworkPolicyReconciler) reconcileNetworkPolicyCreation(
	ctx context.Context, np *v1alpha1.NetworkPolicy, networkPolicy *netv1.NetworkPolicy,
) error {
	current := &netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      np.Name,
			Namespace: np.Namespace,
		},
	}
	op, err := controllerutil.CreateOrUpdate(ctx, r.Client, current, func() error {
		current.Labels = networkPolicy.Labels
		current.Annotations = networkPolicy.Annotations
		current.Spec = networkPolicy.Spec
		return ctrl.SetControllerReference(np, networkPolicy, r.Scheme)
	})
	if err != nil {
		r.EventRecorder.Event(
			np,
			corev1.EventTypeWarning,
			utils.OperationErrorReason(networkPolicy),
			err.Error(),
		)
		return err
	}
	if op != controllerutil.OperationResultNone {
		r.EventRecorder.Event(
			np,
			corev1.EventTypeNormal,
			utils.OperationReason(networkPolicy, op),
			utils.OperationMessage(networkPolicy, op))
	}
	return nil
}
