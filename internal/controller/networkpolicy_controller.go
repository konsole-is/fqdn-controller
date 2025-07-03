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
	"github.com/konsole-is/fqdn-controller/pkg/utils"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/client-go/tools/record"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	v1alpha1 "github.com/konsole-is/fqdn-controller/api/v1alpha1"
)

// NetworkPolicyReconciler reconciles a NetworkPolicy object
type NetworkPolicyReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	EventRecorder record.EventRecorder
}

// +kubebuilder:rbac:groups=fqdn.konsole.is,resources=networkpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=fqdn.konsole.is,resources=networkpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=fqdn.konsole.is,resources=networkpolicies/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.21.0/pkg/reconcile
func (r *NetworkPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = logf.FromContext(ctx)

	np, err := r.getNetworkPolicy(ctx, req)
	if err != nil {
		return ctrl.Result{}, err
	}

	resolver := network.NewDNSResolver(np.Spec.EnabledNetworkType)
	results := resolver.Resolve(np.FQDNs(), time.Duration(np.Spec.ResolveTimeoutSeconds)*time.Second)

	networkPolicy := np.ToNetworkPolicy(results.CIDRLookupTable())

	cidrs := results.CIDRs()
	errors := results.ErrorLookupTable()
	applied := utils.UniqueCidrsInNetworkPolicy(networkPolicy)
	np.Status.SetStatus(cidrs, applied, results.CIDRLookupTable(), errors)

	resolveStatus := results.AggregatedErrorReason()
	resolveMessage := results.AggregatedErrorMessage()

	err = r.reconcileNetworkPolicyCreation(ctx, np, networkPolicy)

	if err != nil {
		np.SetReadyConditionFalse(v1alpha1.NetworkPolicyFailed, "Failed to reconcile NetworkPolicy")
		np.SetResolveCondition(resolveStatus, resolveMessage)
		if err := r.Client.Status().Update(ctx, np); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: time.Duration(np.Spec.TTLSeconds) * time.Second}, nil
	}

	if networkPolicy == nil {
		np.SetReadyConditionFalse(v1alpha1.NetworkPolicyEmptyRules, "Resolve resulted in an empty NetworkPolicy")
		np.SetResolveCondition(resolveStatus, resolveMessage)
		if err := r.Client.Status().Update(ctx, np); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: time.Duration(np.Spec.TTLSeconds) * time.Second}, nil
	}

	np.SetReadyConditionTrue()
	np.SetResolveCondition(resolveStatus, resolveMessage)
	if err := r.Client.Status().Update(ctx, np); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: time.Duration(np.Spec.TTLSeconds) * time.Second}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *NetworkPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.NetworkPolicy{}).
		Named("networkpolicy").
		Owns(&netv1.NetworkPolicy{}).
		Complete(r)
}

// ensureControllerReference Sets controller reference on the given object if it has not been done already
// Returns an error if fails to set controller reference
func (r *NetworkPolicyReconciler) ensureControllerReference(owner *v1alpha1.NetworkPolicy, object client.Object) error {
	for _, ref := range object.GetOwnerReferences() {
		if ref.Controller != nil &&
			*ref.Controller && ref.UID == owner.GetUID() &&
			ref.APIVersion == owner.GetObjectKind().GroupVersionKind().GroupVersion().String() &&
			ref.Kind == owner.GetObjectKind().GroupVersionKind().Kind {
			return nil
		}
	}
	return ctrl.SetControllerReference(owner, object, r.Scheme)
}
