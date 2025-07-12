package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/konsole-is/fqdn-controller/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const startupAnnotationKey = "fqdn-controller.konsole.is/startup-trigger"

var policyQueuer = queueAllNetworkPolicies
var sleepFn = time.Sleep

type manager interface {
	Elected() <-chan struct{}
}

// queueAllNetworkPolicies Triggers a requeue of all network policies in the cluster by setting a label with the
// startupTime in milliseconds as a value
func queueAllNetworkPolicies(ctx context.Context, cli client.Client, startupTime time.Time) error {
	annotationValue := fmt.Sprintf("%d", startupTime.UnixMilli())
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
	if err := cli.List(ctx, &policies, client.MatchingLabelsSelector{Selector: selector}); err != nil {
		return err
	}
	for _, np := range policies.Items {
		patch := client.MergeFrom(np.DeepCopy())
		metav1.SetMetaDataAnnotation(&np.ObjectMeta, startupAnnotationKey, annotationValue)
		if err := cli.Patch(ctx, &np, patch); err != nil {
			return err
		}
	}
	return nil
}

// queueExistingPoliciesOnLeaderElection Ensures that all existing network policies in the cluster are queued into the
// reconciliation loop at their given interval on controller startup. Blocks until leader election has happened.
func (r *NetworkPolicyReconciler) queueExistingPoliciesOnLeaderElection(ctx context.Context, mgr manager) {
	select {
	case <-mgr.Elected():
		logger := logf.FromContext(ctx)
		timeNow := time.Now()
		for {
			err := policyQueuer(ctx, r.Client, timeNow)
			if err == nil {
				return
			}
			logger.Error(err, "Failed to queue network policies on startup, retrying in 2 seconds...")
			sleepFn(2 * time.Second)
		}
	case <-ctx.Done():
		return
	}
}
