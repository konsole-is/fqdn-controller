package utils

import (
	"fmt"
	"reflect"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func typeName(obj interface{}) string {
	t := reflect.TypeOf(obj)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	return t.Name()
}

func OperationErrorReason(object client.Object) string {
	return fmt.Sprintf("%sError", typeName(object))
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
	return fmt.Sprintf("%s%s", typeName(object), reason)
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
	return fmt.Sprintf("%s %s", typeName(object), message)
}

func DeletionReason(object client.Object) string {
	return fmt.Sprintf("%sDeleted", typeName(object))
}

func DeletionMessage(object client.Object) string {
	return fmt.Sprintf("%s was removed", typeName(object))
}
