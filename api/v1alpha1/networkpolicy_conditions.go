package v1alpha1

import (
	"fmt"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

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

func (np *NetworkPolicy) SetReadyConditionFalse(reason NetworkPolicyReadyConditionReason, message string) {
	meta.SetStatusCondition(&np.Status.Conditions, metav1.Condition{
		Type:               string(NetworkPolicyReadyCondition),
		Status:             metav1.ConditionFalse,
		Reason:             string(reason),
		Message:            message,
		ObservedGeneration: np.GetGeneration(),
	})
}
