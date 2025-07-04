package v1alpha1

import (
	"fmt"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SetResolveCondition updates the Resolve condition based on the provided reason and message.
// If the reason indicates success, the status is set to True with a standard success message.
func (np *NetworkPolicy) SetResolveCondition(reason NetworkPolicyResolveConditionReason, message string) {
	condition := metav1.ConditionFalse
	if reason == NetworkPolicyResolveSuccess {
		condition = metav1.ConditionTrue
		message = fmt.Sprintf("The network policy resolved successfully.")
	}
	meta.SetStatusCondition(&np.Status.Conditions, metav1.Condition{
		Type:               string(NetworkPolicyResolveCondition),
		Status:             condition,
		Reason:             string(reason),
		Message:            message,
		ObservedGeneration: np.GetGeneration(),
	})
}

// SetReadyConditionTrue sets the Ready condition to True with a standard success message.
// Updates the ObservedGeneration to reflect the current spec generation.
func (np *NetworkPolicy) SetReadyConditionTrue() {
	meta.SetStatusCondition(&np.Status.Conditions, metav1.Condition{
		Type:               string(NetworkPolicyReadyCondition),
		Status:             metav1.ConditionTrue,
		Reason:             string(NetworkPolicyReady),
		Message:            "The network policy is ready.",
		ObservedGeneration: np.GetGeneration(),
	})
	np.Status.ObservedGeneration = np.GetGeneration()
}

// SetReadyConditionFalse sets the Ready condition to False with the provided reason and message.
func (np *NetworkPolicy) SetReadyConditionFalse(reason NetworkPolicyReadyConditionReason, message string) {
	meta.SetStatusCondition(&np.Status.Conditions, metav1.Condition{
		Type:               string(NetworkPolicyReadyCondition),
		Status:             metav1.ConditionFalse,
		Reason:             string(reason),
		Message:            message,
		ObservedGeneration: np.GetGeneration(),
	})
}
