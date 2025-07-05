package controller

import (
	"context"
	"github.com/konsole-is/fqdn-controller/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"time"
)

const startupAnnotationKey = "fqdn-controller.konsole.is/startup-trigger"

// queueAllNetworkPolicies Triggers a requeue of all network policies in the cluster by setting a label
func (r *NetworkPolicyReconciler) queueAllNetworkPolicies(ctx context.Context, startupTime time.Time) error {
	annotationValue := startupTime.Format(time.RFC3339)
	labelSelector := &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{
			{
				Key:      startupAnnotationKey,
				Operator: metav1.LabelSelectorOpNotIn,
				Values:   []string{annotationValue},
			},
		},
	}
	selector, err := metav1.LabelSelectorAsSelector(labelSelector)
	if err != nil {
		return err
	}
	var policies v1alpha1.NetworkPolicyList
	if err := r.Client.List(ctx, &policies, client.MatchingLabelsSelector{Selector: selector}); err != nil {
		return err
	}
	for _, np := range policies.Items {
		patch := client.MergeFrom(np.DeepCopy())
		metav1.SetMetaDataAnnotation(&np.ObjectMeta, startupAnnotationKey, annotationValue)
		if err := r.Client.Patch(ctx, &np, patch); err != nil {
			return err
		}
	}
	return nil
}

// QueueExistingPoliciesOnLeaderElection Ensures that all existing network policies in the cluster are queued into the
// reconciliation loop at their given interval on controller startup
func (r *NetworkPolicyReconciler) QueueExistingPoliciesOnLeaderElection(ctx context.Context, mgr ctrl.Manager) {
	go func() {
		select {
		case <-mgr.Elected():
			logger := logf.FromContext(ctx)
			timeNow := time.Now()
			for {
				err := r.queueAllNetworkPolicies(ctx, timeNow)
				if err == nil {
					return
				}
				logger.Error(err, "Failed to queue network policies on startup, retrying in 2 seconds...")
				time.Sleep(2 * time.Second)
			}
		case <-ctx.Done():
			return
		}
	}()
}
