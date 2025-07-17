# FQDN Controller

A Helm chart for deploying the `fqdn-controller`, a Kubernetes controller that manages FQDN-based egress 
NetworkPolicies.

Check out the [GitHub Repository](https://github.com/konsole-is/fqdn-controller) for more information.

---

## Prerequisites

1. You must have cert-manager installed
   
## Installation

Install the fqdn-controller CRDs

```bash
curl -sL https://github.com/konsole-is/fqdn-controller/releases/<version>/download/crds.yaml | kubectl apply -f -
```

Install the controller using the helm chart

```bash
helm repo add konsole https://konsole-is.github.io/fqdn-controller/charts
helm repo update
helm install fqdn-controller konsole/fqdn-controller --version <version>
```
