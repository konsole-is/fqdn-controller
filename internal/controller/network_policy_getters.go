package controller

import (
	"context"
	"github.com/konsole-is/fqdn-controller/api/v1alpha1"
	apierrs "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// getNetworkPolicy Retrieves the NetworkPolicy CR according to it's NamespacedName
func (r *NetworkPolicyReconciler) getNetworkPolicy(ctx context.Context, req ctrl.Request) (*v1alpha1.NetworkPolicy, error) {
	logger := logf.FromContext(ctx)
	np := &v1alpha1.NetworkPolicy{}

	if err := r.Get(ctx, req.NamespacedName, np); err != nil {
		if apierrs.IsNotFound(err) {
			logger.Info("resource could no longer be found at reconciliation time.")
			return nil, err
		}

		logger.Error(err, "error fetching fetching resource", "reason", apierrs.ReasonForError(err))
		return nil, err
	}

	return np, nil
}
