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
helm repo add fqdn-controller https://konsole-is.github.io/fqdn-controller/charts
helm install fqdn-controller fqdn-controller/fqdn-controller --version <version>
```

## Verifying chart signatures

All charts are signed using GPG. You can verify the authenticity and integrity of a chart using the .prov file and the 
public GPG key.

```helm
gpg --keyserver hkps://keys.openpgp.org --recv-keys 6D2CDAA28E7B8D360B8C63817D7F57D9C5527906
helm pull konsole/fqdn-controller --version <version> --verify
```