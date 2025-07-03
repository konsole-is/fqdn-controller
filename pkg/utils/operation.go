package utils

import (
	"fmt"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func OperationErrorReason(object client.Object) string {
	return fmt.Sprintf("%TError", object)
}

func OperationReason(object client.Object, op controllerutil.OperationResult) string {
	reason := ""
	switch op {
	case controllerutil.OperationResultCreated:
		reason = "Created"
	case controllerutil.OperationResultUpdated:
		reason = "Updated"
	case controllerutil.OperationResultUpdatedStatus:
		reason = "StatusUpdated"
	case controllerutil.OperationResultUpdatedStatusOnly:
		reason = "StatusUpdated"
	case controllerutil.OperationResultNone:
		reason = "Unchanged"
	}
	return fmt.Sprintf("%T%s", object, reason)
}

func OperationMessage(object client.Object, op controllerutil.OperationResult) string {
	message := ""
	switch op {
	case controllerutil.OperationResultCreated:
		message = "was created"
	case controllerutil.OperationResultUpdated:
		message = "was updated"
	case controllerutil.OperationResultUpdatedStatus:
		message = "had it's status updated"
	case controllerutil.OperationResultUpdatedStatusOnly:
		message = "had it's status updated"
	case controllerutil.OperationResultNone:
		message = "is unchanged"
	}
	return fmt.Sprintf("%T %s", object, message)
}
