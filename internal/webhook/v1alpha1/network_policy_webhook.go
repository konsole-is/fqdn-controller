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

package v1alpha1

import (
	"context"
	"fmt"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	v1alpha1 "github.com/konsole-is/fqdn-controller/api/v1alpha1"
)

// nolint:unused
// log is for logging in this package.
var networkpolicylog = logf.Log.WithName("networkpolicy-resource")

// SetupNetworkPolicyWebhookWithManager registers the webhook for NetworkPolicy in the manager.
func SetupNetworkPolicyWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&v1alpha1.NetworkPolicy{}).
		WithValidator(&NetworkPolicyCustomValidator{}).
		WithDefaulter(&NetworkPolicyCustomDefaulter{}).
		Complete()
}

// TODO(user): EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!

// +kubebuilder:webhook:path=/mutate-fqdn-konsole-is-v1alpha1-networkpolicy,mutating=true,failurePolicy=fail,sideEffects=None,groups=fqdn.konsole.is,resources=networkpolicies,verbs=create;update,versions=v1alpha1,name=mnetworkpolicy-v1alpha1.kb.io,admissionReviewVersions=v1

// NetworkPolicyCustomDefaulter struct is responsible for setting default values on the custom resource of the
// Kind NetworkPolicy when those are created or updated.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as it is used only for temporary operations and does not need to be deeply copied.
type NetworkPolicyCustomDefaulter struct {
	// TODO(user): Add more fields as needed for defaulting
}

var _ webhook.CustomDefaulter = &NetworkPolicyCustomDefaulter{}

// Default implements webhook.CustomDefaulter so a webhook will be registered for the Kind NetworkPolicy.
func (d *NetworkPolicyCustomDefaulter) Default(_ context.Context, obj runtime.Object) error {
	np, ok := obj.(*v1alpha1.NetworkPolicy)

	if !ok {
		return fmt.Errorf("expected an NetworkPolicy object but got %T", obj)
	}
	networkpolicylog.Info("Defaulting for NetworkPolicy", "name", np.GetName())

	return nil
}

// TODO(user): change verbs to "verbs=create;update;delete" if you want to enable deletion validation.
// NOTE: The 'path' attribute must follow a specific pattern and should not be modified directly here.
// Modifying the path for an invalid path can cause API server errors; failing to locate the webhook.
// +kubebuilder:webhook:path=/validate-fqdn-konsole-is-v1alpha1-networkpolicy,mutating=false,failurePolicy=fail,sideEffects=None,groups=fqdn.konsole.is,resources=networkpolicies,verbs=create;update,versions=v1alpha1,name=vnetworkpolicy-v1alpha1.kb.io,admissionReviewVersions=v1

// NetworkPolicyCustomValidator struct is responsible for validating the NetworkPolicy resource
// when it is created, updated, or deleted.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as this struct is used only for temporary operations and does not need to be deeply copied.
type NetworkPolicyCustomValidator struct {
	// TODO(user): Add more fields as needed for validation
}

var _ webhook.CustomValidator = &NetworkPolicyCustomValidator{}

func validateFQDNs(n *v1alpha1.NetworkPolicy) error {
	for i, rule := range n.Spec.Ingress {
		for j, fqdn := range rule.FromFQDNS {
			if !fqdn.Valid() {
				return fmt.Errorf("invalid FQDN '%s' in Ingress[%d].FromFQDNS[%d]", fqdn, i, j)
			}
		}
	}
	for i, rule := range n.Spec.Egress {
		for j, fqdn := range rule.ToFQDNS {
			if !fqdn.Valid() {
				return fmt.Errorf("invalid FQDN '%s' in Egress[%d].ToFQDNS[%d]", fqdn, i, j)
			}
		}
	}
	return nil
}

func validateTimeLimits(n *v1alpha1.NetworkPolicy) error {
	if n.Spec.TTLSeconds < n.Spec.ResolveTimeoutSeconds {
		return fmt.Errorf("TTL seconds must be greater than lookup timeout (%d seconds)", n.Spec.ResolveTimeoutSeconds)
	}
	return nil
}

func validateRuleCount(np *v1alpha1.NetworkPolicy) error {
	if len(np.Spec.Ingress) == 0 && len(np.Spec.Egress) == 0 {
		return fmt.Errorf("at least one of Ingress or Egress rule must be specified")
	}
	return nil
}

func defaultValidation(np *v1alpha1.NetworkPolicy) error {
	if err := validateFQDNs(np); err != nil {
		return err
	}
	if err := validateTimeLimits(np); err != nil {
		return err
	}
	if err := validateRuleCount(np); err != nil {
		return err
	}
	return nil
}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type FQDNNetworkPolicy.
func (v *NetworkPolicyCustomValidator) ValidateCreate(_ context.Context, obj runtime.Object) (admission.Warnings, error) {
	np, ok := obj.(*v1alpha1.NetworkPolicy)
	if !ok {
		return nil, fmt.Errorf("expected a NetworkPolicy object but got %T", obj)
	}
	networkpolicylog.Info("Validation for NetworkPolicy upon creation", "name", np.GetName())

	if err := defaultValidation(np); err != nil {
		return nil, err
	}
	return nil, nil
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type FQDNNetworkPolicy.
func (v *NetworkPolicyCustomValidator) ValidateUpdate(_ context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	np, ok := newObj.(*v1alpha1.NetworkPolicy)
	if !ok {
		return nil, fmt.Errorf("expected a NetworkPolicy object for the newObj but got %T", newObj)
	}
	networkpolicylog.Info("Validation for NetworkPolicy upon update", "name", np.GetName())

	if err := defaultValidation(np); err != nil {
		return nil, err
	}
	return nil, nil
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type NetworkPolicy.
func (v *NetworkPolicyCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	networkpolicy, ok := obj.(*v1alpha1.NetworkPolicy)
	if !ok {
		return nil, fmt.Errorf("expected a NetworkPolicy object but got %T", obj)
	}
	networkpolicylog.Info("Validation for NetworkPolicy upon deletion", "name", networkpolicy.GetName())

	return nil, nil
}
