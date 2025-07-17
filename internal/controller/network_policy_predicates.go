package controller

import (
	"strings"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

const LabelPrefix = "fqdn-controller.konsole.is/"

// ManagedLabelsChangedPredicate is a predicate which returns true if the managed labels of the CR changed
// (Labels prefixed with LabelPrefix)
var ManagedLabelsChangedPredicate = predicate.Funcs{
	UpdateFunc: func(e event.UpdateEvent) bool {
		oldObj := e.ObjectOld.(v1.Object)
		newObj := e.ObjectNew.(v1.Object)
		return fqdnControllerLabelsChanged(oldObj.GetLabels(), newObj.GetLabels())
	},
	CreateFunc: func(e event.CreateEvent) bool { return true },
	DeleteFunc: func(e event.DeleteEvent) bool { return true },
}

// fqdnControllerLabelsChanged Checks for added, removed, or changed LabelPrefix labels
func fqdnControllerLabelsChanged(oldLabels, newLabels map[string]string) bool {
	seen := map[string]struct{}{}

	for k, oldV := range oldLabels {
		if strings.HasPrefix(k, LabelPrefix) {
			seen[k] = struct{}{}
			if newV, ok := newLabels[k]; !ok || newV != oldV {
				// changed or deleted label
				return true
			}
		}
	}

	for k := range newLabels {
		if strings.HasPrefix(k, LabelPrefix) {
			if _, seenBefore := seen[k]; !seenBefore {
				// new label
				return true
			}
		}
	}

	return false
}
