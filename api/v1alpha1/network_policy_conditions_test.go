package v1alpha1

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func Test_SetReadyConditionTrue(t *testing.T) {
	np := &NetworkPolicy{}
	np.Generation = int64(2)
	np.Status.ObservedGeneration = int64(1)
	np.SetReadyConditionTrue()

	cond := meta.FindStatusCondition(np.Status.Conditions, string(NetworkPolicyReadyCondition))
	assert.NotNil(t, cond)
	assert.Equal(t, metav1.ConditionTrue, cond.Status)
	assert.Equal(t, string(NetworkPolicyReady), cond.Reason)
	assert.Equal(t, np.Generation, cond.ObservedGeneration)
	assert.Equal(t, np.Generation, np.Status.ObservedGeneration)
}

func Test_SetReadyConditionFalse(t *testing.T) {
	np := &NetworkPolicy{}
	np.Generation = int64(2)
	np.Status.ObservedGeneration = int64(1)
	np.SetReadyConditionFalse(NetworkPolicyFailed, "Failure!")

	cond := meta.FindStatusCondition(np.Status.Conditions, string(NetworkPolicyReadyCondition))
	assert.NotNil(t, cond)
	assert.Equal(t, metav1.ConditionFalse, cond.Status)
	assert.Equal(t, string(NetworkPolicyFailed), cond.Reason)
	assert.Equal(t, "Failure!", cond.Message)
	assert.Equal(t, np.Generation, cond.ObservedGeneration)
	assert.NotEqual(t, np.Generation, np.Status.ObservedGeneration)
}

func Test_SetResolveCondition_Success(t *testing.T) {
	np := &NetworkPolicy{}
	np.Generation = int64(2)
	np.Status.ObservedGeneration = int64(1)
	np.SetResolveCondition(NetworkPolicyResolveSuccess, "")

	cond := meta.FindStatusCondition(np.Status.Conditions, string(NetworkPolicyResolveCondition))
	assert.NotNil(t, cond)
	assert.Equal(t, metav1.ConditionTrue, cond.Status)
	assert.Equal(t, string(NetworkPolicyResolveSuccess), cond.Reason)
	assert.Equal(t, "The network policy resolved successfully.", cond.Message)
	assert.Equal(t, np.Generation, cond.ObservedGeneration)
	assert.NotEqual(t, np.Generation, np.Status.ObservedGeneration)
}

func Test_SetResolveCondition_Error(t *testing.T) {
	np := &NetworkPolicy{}
	np.Generation = int64(2)
	np.Status.ObservedGeneration = int64(1)
	np.SetResolveCondition(NetworkPolicyResolveDomainNotFound, "Error happened!")

	cond := meta.FindStatusCondition(np.Status.Conditions, string(NetworkPolicyResolveCondition))
	assert.NotNil(t, cond)
	assert.Equal(t, metav1.ConditionFalse, cond.Status)
	assert.Equal(t, string(NetworkPolicyResolveDomainNotFound), cond.Reason)
	assert.Equal(t, "Error happened!", cond.Message)
	assert.Equal(t, np.Generation, cond.ObservedGeneration)
	assert.NotEqual(t, np.Generation, np.Status.ObservedGeneration)
}
