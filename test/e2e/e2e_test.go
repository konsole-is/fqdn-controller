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
	"github.com/konsole-is/fqdn-controller/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

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
		// required if network policy is used, see: config/default/kustomization.yaml
		cmd = exec.Command("kubectl", "label", "--overwrite", "ns", namespace,
			"metrics=enabled")
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

		+kubebuilder:scaffold:e2e-webhooks-checks

		It("should enable egress access to google.com using a FQDN NetworkPolicy", func() {
			httpDomain := "http://google.com"
			httpsDomain := "https://google.com"
			podRef := types.NamespacedName{Name: curlPodName, Namespace: namespace}
			networkPolicyName := "enable-google-egress"
			t := GinkgoT()

			By("verifying curl to google.com succeeds before applying deny-all policy")
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

			By("applying a default deny-all network policy (with kube-dns access)")
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
						netv1.PolicyTypeIngress,
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

			By("observing curl to google.com:80 is blocked")
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
			}).Within(time.Minute).WithPolling(250 * time.Millisecond).Should(Succeed())

			By("applying a NetworkPolicy that allows egress to google.com on port 80")
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
						utils.TCPEgressRule([]v1alpha1.FQDN{"google.com"}, []int{80}),
					},
					BlockPrivateIPs:       false,
					EnabledNetworkType:    v1alpha1.Ipv4,
					TTLSeconds:            30,
					ResolveTimeoutSeconds: 3,
				},
			}
			Expect(utils.KubectlApply(policy)).To(Succeed())

			time.Sleep(3 * time.Second)

			By("observing curl to google.com:80 is allowed")
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

			By("consistently observing curl to google.com:80 is successful")
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

			By("ensuring that curl to google.com:443 is blocked")
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

			By("eventually observing curl to google.com:80 is blocked")
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

		It("should allow ingress access from a pod using a FQDN NetworkPolicy", func() {
			const (
				httpbinName       = "httpbin"
				networkPolicyName = "allow-httpbin-ingress"
			)
			t := GinkgoT()
			httpbinLabels := map[string]string{"app": httpbinName}
			podRef := types.NamespacedName{Name: curlPodName, Namespace: namespace}
			// We allow this FQDN in the ingress rule on the httpbin pod
			curlPodFQDN := fmt.Sprintf("%s.%s.pod.cluster.local", curlPodName, namespace)
			// We curl this from the curlpod
			httpbinFQDN := fmt.Sprintf("%s.%s.svc.cluster.local", httpbinName, namespace)
			targetURL := fmt.Sprintf("http://%s", httpbinFQDN)

			By("deploying a httpbin pod and service")
			httpbin := &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "v1",
					Kind:       "Pod",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      httpbinName,
					Namespace: namespace,
					Labels:    httpbinLabels,
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name:  "httpbin",
						Image: "kennethreitz/httpbin",
						Ports: []corev1.ContainerPort{{ContainerPort: 80}},
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: ptr.To(false),
							RunAsNonRoot:             ptr.To(true),
							RunAsUser:                ptr.To(int64(1001)),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"ALL"},
							},
							SeccompProfile: &corev1.SeccompProfile{
								Type: corev1.SeccompProfileTypeRuntimeDefault,
							},
						},
					}},
				},
			}
			httpbinSvc := &corev1.Service{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "v1",
					Kind:       "Service",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      httpbinName,
					Namespace: namespace,
				},
				Spec: corev1.ServiceSpec{
					Selector: httpbinLabels,
					Ports: []corev1.ServicePort{{
						Port:     80,
						Protocol: corev1.ProtocolTCP,
					}},
				},
			}
			Expect(utils.KubectlApply(httpbin)).To(Succeed())
			Expect(utils.KubectlApply(httpbinSvc)).To(Succeed())
			DeferCleanup(func() {
				_ = utils.KubectlDelete(httpbin)
				_ = utils.KubectlDelete(httpbinSvc)
			})

			By("applying a default deny-all ingress network policy to the httpbin pod")
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
						MatchLabels: httpbinLabels,
					},
					PolicyTypes: []netv1.PolicyType{
						netv1.PolicyTypeIngress,
					},
				},
			}
			Expect(utils.KubectlApply(denyAllPolicy)).To(Succeed())
			DeferCleanup(func() {
				_ = utils.KubectlDelete(denyAllPolicy)
			})

			By("waiting for the httpbin pod to be running")
			Eventually(func() string {
				v, err := utils.KubectlGetJSONPath(httpbin, "pod", ".status.phase")
				if err != nil {
					t.Log(err)
					return ""
				}
				t.Log(v)
				return v
			}).Within(120 * time.Second).WithPolling(5 * time.Second).Should(Equal("Running"))

			By("verifying curl from curlpod to httpbin fails before applying policy")
			Eventually(func(g Gomega) {
				failure, res, err := utils.CurlFailure(podRef, targetURL, 5)
				if err != nil {
					t.Log(err)
				}
				if !failure && err == nil {
					t.Log(res)
				}
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(failure).To(BeTrue())
			}).Within(60 * time.Second).WithPolling(1 * time.Second).Should(Succeed())

			By("applying a FQDN NetworkPolicy that allows ingress to httpbin from curlpod")
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
						MatchLabels: httpbinLabels,
					},
					Ingress: []v1alpha1.IngressRule{
						utils.TCPIngressRule([]v1alpha1.FQDN{v1alpha1.FQDN(curlPodFQDN)}, []int{80}),
					},
					BlockPrivateIPs:       false,
					EnabledNetworkType:    v1alpha1.Ipv4,
					TTLSeconds:            30,
					ResolveTimeoutSeconds: 3,
				},
			}
			Expect(utils.KubectlApply(policy)).To(Succeed())

			By("eventually observing curl to httpbin succeeds")
			Eventually(func(g Gomega) {
				success, res, err := utils.CurlSuccess(podRef, targetURL, 5)
				if err != nil {
					t.Log(err)
				}
				if !success && err == nil {
					t.Log(res)
				}
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(success).To(BeTrue())
			}).Within(60 * time.Second).WithPolling(1 * time.Second).Should(Succeed())

			By("consistently observing curl to httpbin succeeds")
			Consistently(func(g Gomega) {
				success, res, err := utils.CurlSuccess(podRef, targetURL, 5)
				if err != nil {
					t.Log(err)
				}
				if !success && err == nil {
					t.Log(res)
				}
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(success).To(BeTrue())
			}).Within(60 * time.Second).WithPolling(1 * time.Second).Should(Succeed())

			By("deleting the NetworkPolicy to restore access")
			Expect(utils.KubectlDelete(policy)).To(Succeed())

			By("eventually observing curl to httpbin is blocked again")
			Eventually(func(g Gomega) {
				failure, res, err := utils.CurlFailure(podRef, targetURL, 5)
				if err != nil {
					t.Log(err)
				}
				if !failure && err == nil {
					t.Log(res)
				}
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(failure).To(BeTrue())
			}).Should(Succeed())
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
