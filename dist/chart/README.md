# FQDN Controller

A Helm chart for deploying the `fqdn-controller`, a Kubernetes controller that manages FQDN-based egress 
NetworkPolicies.

Check out the [GitHub Repository](https://github.com/konsole-is/fqdn-controller) for more information.

---

## Prerequisites

Install cert-manager in your cluster if you intend to enable webhooks.
   
## Installation

If you wish to manage the CRDs outside the helm chart you can install them with

```bash
curl -sL https://github.com/konsole-is/fqdn-controller/releases/download/<version>/crds.yaml | kubectl apply -f -
```

Install the controller using the helm chart

```bash
helm repo add konsole https://konsole-is.github.io/fqdn-controller/charts
helm repo update
helm install fqdn-controller konsole/fqdn-controller --version <version>
```
