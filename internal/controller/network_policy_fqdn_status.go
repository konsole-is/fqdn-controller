package controller

import (
	"fmt"
	"github.com/konsole-is/fqdn-controller/api/v1alpha1"
	"github.com/konsole-is/fqdn-controller/pkg/network"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	"time"
)

// updateFQDNStatuses updates the status of each FQDN in the network policy according to the results and the previous
// status
func updateFQDNStatuses(
	recorder record.EventRecorder, object runtime.Object,
	previous []v1alpha1.FQDNStatus, results network.DNSResolverResultList,
	retryTimeoutSeconds int,
) []v1alpha1.FQDNStatus {
	var newFQDNStatuses []v1alpha1.FQDNStatus
	previousLookup := v1alpha1.FQDNStatusList(previous).LookupTable()

	for _, result := range results {
		if status, ok := previousLookup[result.Domain]; ok {
			cleared := status.Update(result.CIDRs, result.Status, result.Message, retryTimeoutSeconds)
			newFQDNStatuses = append(newFQDNStatuses, *status)

			if cleared {
				timeNow := time.Now()
				recorder.Event(
					object, corev1.EventTypeWarning, "FQDNRemoved",
					fmt.Sprintf(
						"IP Addresses of FQDN %s removed after being stale for %s. "+
							"Resolve status at removal time was %s (for %s). "+
							"Last successful resolve time was %s ago.",
						status.FQDN, (time.Duration(retryTimeoutSeconds)*time.Second).String(),
						status.ResolveReason, timeNow.Sub(status.LastTransitionTime.Time).String(),
						timeNow.Sub(status.LastSuccessfulTime.Time).String(),
					),
				)
			}
		} else {
			newFQDNStatuses = append(newFQDNStatuses, v1alpha1.NewFQDNStatus(
				result.Domain,
				result.CIDRs,
				result.Status,
				result.Message,
			))
		}
	}
	return newFQDNStatuses
}
