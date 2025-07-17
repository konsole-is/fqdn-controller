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

package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"

	"github.com/konsole-is/fqdn-controller/api/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/konsole-is/fqdn-controller/test/utils"
)

// namespace where the project is deployed in
const namespace = "fqdn-controller-system"

// serviceAccountName created for the project
const serviceAccountName = "fqdn-controller-controller-manager"

// metricsServiceName is the name of the metrics service of the project
const metricsServiceName = "fqdn-controller-controller-manager-metrics-service"

// metricsRoleBindingName is the name of the RBAC that will be created to allow get the metrics data
const metricsRoleBindingName = "fqdn-controller-metrics-binding"

const controllerName = "fqdn-controller-controller-manager"

var _ = Describe("Manager", Ordered, func() {
	var (
		controllerPodName string
		curlPodName       string
		curlPodLabels     map[string]string
	)

	// Before running the tests, set up the environment by creating the namespace,
	// enforce the restricted security policy to the namespace, installing CRDs,
	// and deploying the controller.
	BeforeAll(func() {
		By("creating manager namespace")
		cmd := exec.Command("kubectl", "create", "ns", namespace)
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to create namespace")

		By("labeling the namespace to enforce the restricted security policy")
		cmd = exec.Command("kubectl", "label", "--overwrite", "ns", namespace,
			"pod-security.kubernetes.io/enforce=restricted")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to label for restricted security policy")

		// required if network policy is used, see: config/default/kustomization.yaml
		cmd = exec.Command("kubectl", "label", "--overwrite", "ns", namespace,
			"metrics=enabled")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to label for metrics")

		cmd = exec.Command("kubectl", "label", "--overwrite", "ns", namespace,
			"webhooks=enabled")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to label namespace with restricted policy")

		By("installing CRDs")
		cmd = exec.Command("make", "install")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to install CRDs")

		By("deploying the controller-manager")
		cmd = exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", projectImage))
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy the controller-manager")

		By("creating long-lived curl pod for network testing")
		curlPodName = "test-curl"
		curlPodLabels = map[string]string{"app": "curl"}
		curlPod := utils.NewCurlPod("test-curl", namespace, curlPodLabels)
		err = utils.KubectlApply(curlPod)
		Expect(err).NotTo(HaveOccurred())

		By("waiting for the curl pod to be running")
		t := GinkgoT()
		Eventually(func() string {
			v, err := utils.KubectlGetJSONPath(curlPod, "pod", ".status.phase")
			if err != nil {
				t.Log(err)
				return ""
			}
			t.Log(fmt.Sprintf("Pod status: %s", v))
			return v
		}).Should(Equal("Running"))
	})

	// After all tests have been executed, clean up by undeploying the controller, uninstalling CRDs,
	// and deleting the namespace.
	AfterAll(func() {
		By("cleaning up the curl pod for metrics")
		cmd := exec.Command("kubectl", "delete", "pod", "curl-metrics", "-n", namespace)
		_, _ = utils.Run(cmd)

		By("undeploying the controller-manager")
		cmd = exec.Command("make", "undeploy")
		_, _ = utils.Run(cmd)

		By("uninstalling CRDs")
		cmd = exec.Command("make", "uninstall")
		_, _ = utils.Run(cmd)

		By("removing manager namespace")
		cmd = exec.Command("kubectl", "delete", "ns", namespace)
		_, _ = utils.Run(cmd)

		By("removing the curlpod")
		cmd = exec.Command("kubectl", "delete", "pod", curlPodName, "-n", namespace)
		_, _ = utils.Run(cmd)
	})

	// After each test, check for failures and collect logs, events,
	// and pod descriptions for debugging.
	AfterEach(func() {
		specReport := CurrentSpecReport()
		if specReport.Failed() {
			By("Fetching controller manager pod logs")
			cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace)
			controllerLogs, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Controller logs:\n %s", controllerLogs)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get Controller logs: %s", err)
			}

			By("Fetching Kubernetes events")
			cmd = exec.Command("kubectl", "get", "events", "-n", namespace, "--sort-by=.lastTimestamp")
			eventsOutput, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Kubernetes events:\n%s", eventsOutput)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get Kubernetes events: %s", err)
			}

			By("Fetching curl-metrics logs")
			cmd = exec.Command("kubectl", "logs", "curl-metrics", "-n", namespace)
			metricsOutput, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Metrics logs:\n %s", metricsOutput)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get curl-metrics logs: %s", err)
			}

			By("Fetching controller manager pod description")
			cmd = exec.Command("kubectl", "describe", "pod", controllerPodName, "-n", namespace)
			podDescription, err := utils.Run(cmd)
			if err == nil {
				fmt.Println("Pod description:\n", podDescription)
			} else {
				fmt.Println("Failed to describe controller pod")
			}

			By("Fetching FQDN Network policies")
			cmd = exec.Command("kubectl", "get", "fqdn", "-n", namespace, "-o", "yaml")
			fqdn, err := utils.Run(cmd)
			if err == nil {
				fmt.Println("FQDN Network policies:\n", fqdn)
			} else {
				fmt.Println("Failed to get FQDN Network policies")
			}

			By("Fetching Network policies")
			cmd = exec.Command("kubectl", "get", "networkpolicy", "-n", namespace, "-o", "yaml")
			nps, err := utils.Run(cmd)
			if err == nil {
				fmt.Println("Network policies:\n", nps)
			} else {
				fmt.Println("Failed to get Network policies")
			}
		}
	})

	SetDefaultEventuallyTimeout(2 * time.Minute)
	SetDefaultEventuallyPollingInterval(time.Second)

	Context("Manager", func() {
		It("should run successfully", func() {
			By("validating that the controller-manager pod is running as expected")
			verifyControllerUp := func(g Gomega) {
				// Get the name of the controller-manager pod
				cmd := exec.Command("kubectl", "get",
					"pods", "-l", "control-plane=controller-manager",
					"-o", "go-template={{ range .items }}"+
						"{{ if not .metadata.deletionTimestamp }}"+
						"{{ .metadata.name }}"+
						"{{ \"\\n\" }}{{ end }}{{ end }}",
					"-n", namespace,
				)

				podOutput, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to retrieve controller-manager pod information")
				podNames := utils.GetNonEmptyLines(podOutput)
				g.Expect(podNames).To(HaveLen(1), "expected 1 controller pod running")
				controllerPodName = podNames[0]
				g.Expect(controllerPodName).To(ContainSubstring("controller-manager"))

				// Validate the pod's status
				cmd = exec.Command("kubectl", "get",
					"pods", controllerPodName, "-o", "jsonpath={.status.phase}",
					"-n", namespace,
				)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Running"), "Incorrect controller-manager pod status")
			}
			Eventually(verifyControllerUp).Should(Succeed())
		})

		It("should ensure the metrics endpoint is serving metrics", func() {
			By("creating a ClusterRoleBinding for the service account to allow access to metrics")
			cmd := exec.Command("kubectl", "create", "clusterrolebinding", metricsRoleBindingName,
				"--clusterrole=fqdn-controller-metrics-reader",
				fmt.Sprintf("--serviceaccount=%s:%s", namespace, serviceAccountName),
			)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create ClusterRoleBinding")

			By("validating that the metrics service is available")
			cmd = exec.Command("kubectl", "get", "service", metricsServiceName, "-n", namespace)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Metrics service should exist")

			By("getting the service account token")
			token, err := serviceAccountToken()
			Expect(err).NotTo(HaveOccurred())
			Expect(token).NotTo(BeEmpty())

			By("waiting for the metrics endpoint to be ready")
			verifyMetricsEndpointReady := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "endpoints", metricsServiceName, "-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("8443"), "Metrics endpoint is not ready")
			}
			Eventually(verifyMetricsEndpointReady).Should(Succeed())

			By("verifying that the controller manager is serving the metrics server")
			verifyMetricsServerStarted := func(g Gomega) {
				cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("controller-runtime.metrics\tServing metrics server"),
					"Metrics server not yet started")
			}
			Eventually(verifyMetricsServerStarted).Should(Succeed())

			By("creating the curl-metrics pod to access the metrics endpoint")
			cmd = exec.Command("kubectl", "run", "curl-metrics", "--restart=Never",
				"--namespace", namespace,
				"--image=curlimages/curl:latest",
				"--overrides",
				fmt.Sprintf(`{
					"spec": {
						"containers": [{
							"name": "curl",
							"image": "curlimages/curl:latest",
							"command": ["/bin/sh", "-c"],
							"args": ["curl -v -k -H 'Authorization: Bearer %s' https://%s.%s.svc.cluster.local:8443/metrics"],
							"securityContext": {
								"allowPrivilegeEscalation": false,
								"capabilities": {
									"drop": ["ALL"]
								},
								"runAsNonRoot": true,
								"runAsUser": 1000,
								"seccompProfile": {
									"type": "RuntimeDefault"
								}
							}
						}],
						"serviceAccount": "%s"
					}
				}`, token, metricsServiceName, namespace, serviceAccountName))
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create curl-metrics pod")

			By("waiting for the curl-metrics pod to complete.")
			verifyCurlUp := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pods", "curl-metrics",
					"-o", "jsonpath={.status.phase}",
					"-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Succeeded"), "curl pod in wrong status")
			}
			Eventually(verifyCurlUp, 2*time.Minute).Should(Succeed())

			By("getting the metrics by checking curl-metrics logs")
			metricsOutput := getMetricsOutput()
			Expect(metricsOutput).To(ContainSubstring(
				"controller_runtime_reconcile_total",
			))
		})

		It("should provisioned cert-manager", func() {
			By("validating that cert-manager has the certificate Secret")
			verifyCertManager := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "secrets", "webhook-server-cert", "-n", namespace)
				_, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
			}
			Eventually(verifyCertManager).Should(Succeed())
		})

		It("should have CA injection for mutating webhooks", func() {
			By("checking CA injection for mutating webhooks")
			verifyCAInjection := func(g Gomega) {
				cmd := exec.Command("kubectl", "get",
					"mutatingwebhookconfigurations.admissionregistration.k8s.io",
					"fqdn-controller-mutating-webhook-configuration",
					"-o", "go-template={{ range .webhooks }}{{ .clientConfig.caBundle }}{{ end }}")
				mwhOutput, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(len(mwhOutput)).To(BeNumerically(">", 10))
			}
			Eventually(verifyCAInjection).Should(Succeed())
		})

		It("should have CA injection for validating webhooks", func() {
			By("checking CA injection for validating webhooks")
			verifyCAInjection := func(g Gomega) {
				cmd := exec.Command("kubectl", "get",
					"validatingwebhookconfigurations.admissionregistration.k8s.io",
					"fqdn-controller-validating-webhook-configuration",
					"-o", "go-template={{ range .webhooks }}{{ .clientConfig.caBundle }}{{ end }}")
				vwhOutput, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(len(vwhOutput)).To(BeNumerically(">", 10))
			}
			Eventually(verifyCAInjection).Should(Succeed())
		})

		// +kubebuilder:scaffold:e2e-webhooks-checks

		It("should enable egress access to example.com using a FQDN NetworkPolicy", func() {
			httpDomain := "http://example.com"
			httpsDomain := "https://example.com"
			podRef := types.NamespacedName{Name: curlPodName, Namespace: namespace}
			networkPolicyName := "enable-example-egress"
			t := GinkgoT()

			By("verifying curl to example.com succeeds before applying deny-all policy")
			Eventually(func(g Gomega) {
				success, res, err := utils.CurlSuccess(podRef, httpDomain, 5)
				if err != nil {
					t.Log(err)
				}
				if !success && err == nil {
					t.Log(res)
				}
				g.Expect(err).NotTo(HaveOccurred(), "curl to %s should succeed initially", httpDomain)
				g.Expect(success).To(BeTrue(), "expected curl to %s to succeed", httpDomain)
			}).WithTimeout(30 * time.Second).WithPolling(250 * time.Millisecond).Should(Succeed())

			By("applying a default deny-all egress network policy (with kube-dns access)")
			denyAllPolicyName := "deny-all"
			denyAllPolicy := &netv1.NetworkPolicy{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "networking.k8s.io/v1",
					Kind:       "NetworkPolicy",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      denyAllPolicyName,
					Namespace: namespace,
				},
				Spec: netv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{
						MatchLabels: curlPodLabels,
					},
					PolicyTypes: []netv1.PolicyType{
						netv1.PolicyTypeEgress,
					},
					Egress: []netv1.NetworkPolicyEgressRule{
						{
							To: []netv1.NetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"kubernetes.io/metadata.name": "kube-system",
										},
									},
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"k8s-app": "kube-dns",
										},
									},
								},
							},
							Ports: []netv1.NetworkPolicyPort{
								{
									Protocol: func() *corev1.Protocol {
										proto := corev1.ProtocolUDP
										return &proto
									}(),
									Port: ptr.To(intstr.FromInt32(int32(53))),
								},
								{
									Protocol: func() *corev1.Protocol {
										proto := corev1.ProtocolTCP
										return &proto
									}(),
									Port: ptr.To(intstr.FromInt32(int32(53))),
								},
							},
						},
					},
				},
			}
			Expect(utils.KubectlApply(denyAllPolicy)).To(Succeed())
			DeferCleanup(func() {
				_ = utils.KubectlDelete(denyAllPolicy)
			})

			By("observing curl to example.com:80 is blocked")
			Eventually(func(g Gomega) {
				failure, res, err := utils.CurlFailure(podRef, httpDomain, 5)
				if err != nil {
					t.Log(err)
				}
				if !failure && err == nil {
					t.Log(res)
				}
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(failure).To(BeTrue(), "expected curl to %s to fail", httpDomain)
			}).Within(60 * time.Second).WithPolling(time.Second).Should(Succeed())

			By("applying a NetworkPolicy that allows egress to example.com on port 80")
			policy := &v1alpha1.NetworkPolicy{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "fqdn.konsole.is/v1alpha1",
					Kind:       "NetworkPolicy",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      networkPolicyName,
					Namespace: namespace,
				},
				Spec: v1alpha1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{
						MatchLabels: curlPodLabels,
					},
					Egress: []v1alpha1.EgressRule{
						utils.TCPEgressRule([]v1alpha1.FQDN{"example.com"}, []int{80}),
					},
					BlockPrivateIPs:       false,
					EnabledNetworkType:    v1alpha1.Ipv4,
					TTLSeconds:            30,
					ResolveTimeoutSeconds: 2,
				},
			}
			Expect(utils.KubectlApply(policy)).To(Succeed())

			time.Sleep(3 * time.Second)

			By("observing curl to example.com:80 is allowed")
			Eventually(func(g Gomega) {
				success, res, err := utils.CurlSuccess(podRef, httpDomain, 5)
				if err != nil {
					t.Log(err)
				}
				if !success && err == nil {
					t.Log(res)
				}
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(success).To(BeTrue(), "expected curl to %s to succeed", httpDomain)
			}).Within(60 * time.Second).WithPolling(1 * time.Second).Should(Succeed())

			By("consistently observing curl to example.com:80 is successful")
			Consistently(func(g Gomega) {
				success, res, err := utils.CurlSuccess(podRef, httpDomain, 5)
				if err != nil {
					t.Log(err)
				}
				if !success && err == nil {
					t.Log(res)
				}
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(success).To(BeTrue(), "expected curl to %s to succeed", httpDomain)
			}).Within(60 * time.Second).WithPolling(1 * time.Second).Should(Succeed())

			By("ensuring that curl to example.com:443 is blocked")
			Eventually(func(g Gomega) {
				failure, res, err := utils.CurlFailure(podRef, httpsDomain, 5)
				if err != nil {
					t.Log(err)
				}
				if !failure && err == nil {
					t.Log(res)
				}
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(failure).To(BeTrue(), "expected curl to %s to fail", httpsDomain)
			}).Within(60 * time.Second).WithPolling(1 * time.Second).Should(Succeed())

			By("deleting the NetworkPolicy")
			Expect(utils.KubectlDelete(policy)).To(Succeed())

			By("eventually observing curl to example.com:80 is blocked")
			Eventually(func(g Gomega) {
				failure, res, err := utils.CurlFailure(podRef, httpDomain, 5)
				if err != nil {
					t.Log(err)
				}
				if !failure && err == nil {
					t.Log(res)
				}
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(failure).To(BeTrue(), "expected curl to %s fail after deleting the policy", httpDomain)
			}).Within(60 * time.Second).WithPolling(1 * time.Second).Should(Succeed())
		})

		It("should reconcile FQDN network policies after restart", func() {
			t := GinkgoT()
			const policyNamespace = "test-policy-namespace"

			By("creating the network policy namespace")
			cmd := exec.Command("kubectl", "create", "namespace", policyNamespace)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() {
				cmd = exec.Command("kubectl", "delete", "namespace", policyNamespace)
				_, err = utils.Run(cmd)
			})

			By("Creating two FQDN network policies")
			policy1 := &v1alpha1.NetworkPolicy{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "fqdn.konsole.is/v1alpha1",
					Kind:       "NetworkPolicy",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "reconcile-test-1",
					Namespace: policyNamespace,
				},
				Spec: v1alpha1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: curlPodLabels},
					Egress: []v1alpha1.EgressRule{
						utils.TCPEgressRule([]v1alpha1.FQDN{"example.com"}, []int{80}),
					},
					BlockPrivateIPs:       false,
					EnabledNetworkType:    v1alpha1.Ipv4,
					TTLSeconds:            60,
					ResolveTimeoutSeconds: 2,
				},
			}
			policy2 := policy1.DeepCopy()
			policy2.Name = "reconcile-test-2"
			Expect(utils.KubectlApply(policy1)).To(Succeed())
			Expect(utils.KubectlApply(policy2)).To(Succeed())

			DeferCleanup(func() {
				_ = utils.KubectlDelete(policy1)
				_ = utils.KubectlDelete(policy2)
			})

			By("Waiting for both policies to have .status.latestLookupTime populated")
			for _, p := range []*v1alpha1.NetworkPolicy{policy1, policy2} {
				Eventually(func(g Gomega) {
					lookupTime, err := utils.KubectlGetJSONPath(p, "fqdn", ".status.latestLookupTime")
					t.Log(lookupTime)
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(lookupTime).NotTo(BeEmpty())
				}).WithTimeout(60 * time.Second).Should(Succeed())
			}

			By("scaling controller manager to zero")
			cmd = exec.Command("kubectl", "scale", "deployment", controllerName, "-n", namespace, "--replicas=0")
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to scale down the controller-manager")

			By("waiting for controller manager pods to be gone")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pods",
					"-l", "control-plane=controller-manager",
					"-n", namespace,
					"-o", "jsonpath={.items[*].status.phase}",
				)
				out, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(out).To(BeEmpty(), "Expected no controller-manager pods to be running")
			}).WithTimeout(30 * time.Second).Should(Succeed())

			By("noting the FQDN policy last lookup time")
			lookupBefore := make(map[string]string)
			for _, p := range []*v1alpha1.NetworkPolicy{policy1, policy2} {
				lookupTime, err := utils.KubectlGetJSONPath(p, "fqdn", ".status.latestLookupTime")
				Expect(err).NotTo(HaveOccurred())
				lookupBefore[p.Name] = lookupTime
			}

			By("scaling up the controller manager")
			cmd = exec.Command("kubectl", "scale", "deployment", controllerName, "-n", namespace, "--replicas=2")
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to scale up the controller-manager")

			By("validating that the controller-manager pod is running as expected")
			verifyControllerUp := func(g Gomega) {
				// Get the name of the controller-manager pod
				cmd := exec.Command("kubectl", "get",
					"pods", "-l", "control-plane=controller-manager",
					"-o", "go-template={{ range .items }}"+
						"{{ if not .metadata.deletionTimestamp }}"+
						"{{ .metadata.name }}"+
						"{{ \"\\n\" }}{{ end }}{{ end }}",
					"-n", namespace,
				)

				podOutput, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to retrieve controller-manager pod information")
				podNames := utils.GetNonEmptyLines(podOutput)
				g.Expect(podNames).To(HaveLen(2), "expected 2 controller pods running")
				controllerPodName = podNames[0]
				g.Expect(controllerPodName).To(ContainSubstring("controller-manager"))

				// Validate the pod's status
				cmd = exec.Command("kubectl", "get",
					"pods", controllerPodName, "-o", "jsonpath={.status.phase}",
					"-n", namespace,
				)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Running"), "Incorrect controller-manager pod status")
			}
			Eventually(verifyControllerUp).Should(Succeed())

			By("asserting that the network policy latest lookup time changes")
			for _, p := range []*v1alpha1.NetworkPolicy{policy1, policy2} {
				Eventually(func(g Gomega) {
					newGen, err := utils.KubectlGetJSONPath(p, "fqdn", ".status.latestLookupTime")
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(newGen).ToNot(BeEmpty())
					g.Expect(newGen).ToNot(Equal(lookupBefore[p.Name]))
				}).WithTimeout(60*time.Second).Should(Succeed(), "Latest lookup time should change")
			}
		})
	})
})

// serviceAccountToken returns a token for the specified service account in the given namespace.
// It uses the Kubernetes TokenRequest API to generate a token by directly sending a request
// and parsing the resulting token from the API response.
func serviceAccountToken() (string, error) {
	const tokenRequestRawString = `{
		"apiVersion": "authentication.k8s.io/v1",
		"kind": "TokenRequest"
	}`

	// Temporary file to store the token request
	secretName := fmt.Sprintf("%s-token-request", serviceAccountName)
	tokenRequestFile := filepath.Join("/tmp", secretName)
	err := os.WriteFile(tokenRequestFile, []byte(tokenRequestRawString), os.FileMode(0o644))
	if err != nil {
		return "", err
	}

	var out string
	verifyTokenCreation := func(g Gomega) {
		// Execute kubectl command to create the token
		cmd := exec.Command("kubectl", "create", "--raw", fmt.Sprintf(
			"/api/v1/namespaces/%s/serviceaccounts/%s/token",
			namespace,
			serviceAccountName,
		), "-f", tokenRequestFile)

		output, err := cmd.CombinedOutput()
		g.Expect(err).NotTo(HaveOccurred())

		// Parse the JSON output to extract the token
		var token tokenRequest
		err = json.Unmarshal(output, &token)
		g.Expect(err).NotTo(HaveOccurred())

		out = token.Status.Token
	}
	Eventually(verifyTokenCreation).Should(Succeed())

	return out, err
}

// getMetricsOutput retrieves and returns the logs from the curl pod used to access the metrics endpoint.
func getMetricsOutput() string {
	By("getting the curl-metrics logs")
	cmd := exec.Command("kubectl", "logs", "curl-metrics", "-n", namespace)
	metricsOutput, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to retrieve logs from curl pod")
	Expect(metricsOutput).To(ContainSubstring("< HTTP/1.1 200 OK"))
	return metricsOutput
}

// tokenRequest is a simplified representation of the Kubernetes TokenRequest API response,
// containing only the token field that we need to extract.
type tokenRequest struct {
	Status struct {
		Token string `json:"token"`
	} `json:"status"`
}
