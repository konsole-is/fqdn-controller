# fqdn-controller

[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/fqdn-controller)](https://artifacthub.io/packages/search?repo=fqdn-controller)
[![Go Report Card](https://goreportcard.com/badge/github.com/konsole-is/fqdn-controller)](https://goreportcard.com/report/github.com/konsole-is/fqdn-controller)
[![License](https://img.shields.io/github/license/konsole-is/fqdn-controller)](LICENSE)

Traditional Kubernetes NetworkPolicy objects do not support rules based on fully qualified domain names (FQDNs).
As a result, teams often resort to installing complex solutions like Cilium, custom VPC CNIs, or service meshes 
introducing operational overhead, additional dependencies, and deeper integration into the cluster network stack.

fqdn-controller addresses this gap by extending Kubernetes with a controller that dynamically resolves FQDNs to IPs 
and maintains them in standard NetworkPolicy objects. It avoids invasive networking changes and works with the default 
CNI, making it suitable for clusters running in the cloud or in environments where simplicity and portability are 
priorities.

---

## ✨ Features

- Create `NetworkPolicy` egress rules based on FQDNs
- Automatically resolve and refresh IPs on a configurable schedule
- Optionally filter private IPs to enforce security policies
- Supports IPv4, IPv6, or both
- Helm chart available via Artifact Hub

---

## 🚀 Installation

### Helm installation

If you wish to manage the CRDs outside the helm chart you can install them with

```bash
curl -sL https://github.com/konsole-is/fqdn-controller/releases/download/<version>/crds.yaml | kubectl apply -f -
```

Chart installation

```bash
helm repo add konsole https://konsole-is.github.io/fqdn-controller/charts
helm repo update
helm install fqdn-controller konsole/fqdn-controller --version <version>
```

### Kubectl installation

```bash
curl -sL https://github.com/konsole-is/fqdn-controller/releases/download/<version>/install.yaml | kubectl apply -f -
```

Note: Will contain only 1 replica unless modified.

## 🛠 Configuration options

| Field                   | Description                                                               |
|-------------------------|---------------------------------------------------------------------------|
| `ttlSeconds`            | Frequency (in seconds) to re-resolve FQDNs. Default: `60`                 |
| `resolveTimeoutSeconds` | Timeout (in seconds) for each DNS lookup. Default: `3`                    |
| `retryTimeoutSeconds`   | Retry window for failed resolutions before dropping IPs. Default: `3600`  |
| `blockPrivateIPs`       | Whether to exclude RFC1918/private IPs from resolved results              |
| `enabledNetworkType`    | IP address type to allow: one of `ipv4`, `ipv6`, or `all`. Default: `all` |


## 🧾 Custom Resource Example

```yaml
apiVersion: fqdn.konsole.is/v1alpha1
kind: NetworkPolicy
metadata:
  name: networkpolicy-sample
  namespace: default
spec:
  podSelector:
    matchLabels:
      app: my-app
  enabledNetworkType: ipv4
  ttlSeconds: 60
  resolveTimeoutSeconds: 3
  retryTimeoutSeconds: 3600
  blockPrivateIPs: false
  egress:
    - toFQDNS:
        - api.example.com
        - github.com
      ports:
        - protocol: TCP
          port: 443
    - toFQDNS:
        - telemetry.example.net
      ports:
        - protocol: TCP
          port: 443
      blockPrivateIPs: true
```

## 🧪 Development

The repository is configured for [ASDF](https://asdf-vm.com/) to install project dependencies.

Run `make help` for information on development commands.

## 📦 Releases

- Helm Chart: [Artifact Hub]()
- CRD Bundle: [GitHub Releases](https://github.com/konsole-is/fqdn-controller/releases)
- Release manifest: [GitHub Releases](https://github.com/konsole-is/fqdn-controller/releases)

## 🤝 Contributing

Contributions, bug reports, and feedback are welcome!
Please open issues or pull requests as needed.