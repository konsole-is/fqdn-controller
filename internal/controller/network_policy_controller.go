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

	"github.com/konsole-is/fqdn-controller/api/v1alpha1"
)

// DNSResolver resolves domains to IP addresses
type DNSResolver interface {
	// Resolve all the given fqdns to a DNSResolverResult
	Resolve(fqdns []v1alpha1.FQDN, timeout time.Duration, networkType v1alpha1.NetworkType) network.DNSResolverResultList
}

// NetworkPolicyReconciler reconciles a NetworkPolicy object
type NetworkPolicyReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	EventRecorder record.EventRecorder
	DNSResolver   DNSResolver
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
	np := &v1alpha1.NetworkPolicy{}
	if err := r.Get(ctx, req.NamespacedName, np); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	// Resolve the FQDNs to IP addresses
	resolveTimeout := time.Duration(np.Spec.ResolveTimeoutSeconds) * time.Second
	results := r.DNSResolver.Resolve(np.FQDNs(), resolveTimeout, np.Spec.EnabledNetworkType)

	// Generate a network policy from the FQDN based network policy using the resolved addresses
	networkPolicy := np.ToNetworkPolicy(results.CIDRLookupTable())

	// Set the status fields of the fqdn network policy
	np.Status.SetStatusFields(
		results.CIDRs(),
		utils.UniqueCidrsInNetworkPolicy(networkPolicy),
		results.CIDRLookupTable(),
		results.ErrorLookupTable(),
	)
	// Set the resolve status condition
	np.SetResolveCondition(
		results.AggregatedErrorReason(),
		results.AggregatedErrorMessage(),
	)

	logger := logf.FromContext(ctx).WithValues(
		"policy", np.GetName(), "namespace", np.GetNamespace(),
		"resolved", np.Status.TotalAddressCount,
		"blocked", np.Status.BlockedAddressCount,
		"applied", np.Status.AppliedAddressCount,
	)
	logf.IntoContext(ctx, logger)

	// The network policy is nil when there are no valid Ingress or Egress rules resolved
	// We delete the underlying network policy because it is no longer valid and requeue after TTL
	if networkPolicy == nil {
		np.SetReadyConditionFalse(v1alpha1.NetworkPolicyEmptyRules, "Resolved to an empty NetworkPolicy")
		if err := r.Client.Status().Update(ctx, np); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.reconcileNetworkPolicyDeletion(ctx, np); err != nil {
			return ctrl.Result{}, err
		}
		logger.Info("Network policy was empty", "requeueAfter", np.Spec.TTLSeconds)
		return ctrl.Result{RequeueAfter: time.Duration(np.Spec.TTLSeconds) * time.Second}, nil
	}

	// There are valid Ingress or Egress rules in the network policy, we create or update it
	if err := r.reconcileNetworkPolicyCreation(ctx, np, networkPolicy); err != nil {
		np.SetReadyConditionFalse(v1alpha1.NetworkPolicyFailed, err.Error())
		if err := r.Client.Status().Update(ctx, np); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, err
	}

	// Creation succeeded, update the status and requeue after TTL
	np.SetReadyConditionTrue()
	if err := r.Client.Status().Update(ctx, np); err != nil {
		return ctrl.Result{}, err
	}
	logger.Info("Reconciliation succeeded", "requeueAfter", np.Spec.TTLSeconds)
	return ctrl.Result{RequeueAfter: time.Duration(np.Spec.TTLSeconds) * time.Second}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *NetworkPolicyReconciler) SetupWithManager(mgr ctrl.Manager, ctx context.Context) error {
	// Note that we can safely call this from here because we are waiting for leader election in the function
	// If leader election is not enabled, mrg.Elected() returns once mgr.Start() has been called, which happens
	// after we return from SetupWithManager
	r.QueueExistingPoliciesOnLeaderElection(ctx, mgr)

	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.NetworkPolicy{}).
		Named("fqdnnetworkpolicy").
		Owns(&netv1.NetworkPolicy{}).
		Complete(r)
}
