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

## 📚 Table of Contents

- [✨ Features](#-features)
- [⚠️ Limitations](#-limitations)
- [🧾 CRD Overview](#-crd-overview)
    - [Important Behavior Notes](#important-behavior-notes)
    - [Resource Kind & Short Name](#resource-kind--short-name)
    - [Key Fields](#key-fields)
    - [IP Filtering](#ip-filtering)
    - [IP Retention on Failure](#ip-retention-on-failure)
    - [Status and Observability](#status-and-observability)
- [📄 Custom Resource Example](#custom-resource-example)
- [🚀 Installation](#-installation)
    - [Helm Installation](#helm-installation)
    - [Kubectl Installation](#kubectl-installation)
- [🧪 Development](#-development)
- [📦 Releases](#-releases)
- [🤝 Contributing](#-contributing)

---

## ✨ Features

- Create `NetworkPolicy` egress rules based on FQDNs
- Automatically resolve and refresh IPs on a configurable schedule
- Optionally filter private IPs to enforce security policies
- Supports IPv4, IPv6, or both
- Helm chart available via Artifact Hub

---

## ⚠️ Limitations

The controller is not suitable for domains with highly dynamic IP resolution. For example, domains like google.com may return different IPs every few minutes. If your workloads rely on consistent IP connectivity to such domains and cannot tolerate brief network disruptions, this operator may not meet your needs.

That said, domains with mostly static IPs, but that may occasionally change, can still work well. In such cases, network connectivity may be briefly interrupted during the window between an IP change and the next successful DNS resolution. The duration of this outage is at most equal to the ttlSeconds value specified in your policy.

---

## 🧾 CRD Overview

The NetworkPolicy custom resource allows you to specify egress rules by domain name. The controller performs DNS
resolution on these FQDNs and applies the resolved IPs into [standard Kubernetes NetworkPolicy objects](https://kubernetes.io/docs/concepts/services-networking/network-policies/).

> [!IMPORTANT]
>  If your pods rely on DNS, you must define a separate policy that allows egress to CoreDNS or KubeDNS.
>  Since you are considering an FQDN based egress policy, this is highly likely the case.

> [!IMPORTANT]
> **No IPs = Egress Deny All**. If no IPs are resolved for a rule, egress traffic is blocked. This conforms with standard 
> Kubernetes NetworkPolicy behavior.

### Resource Kind & Short Name

This controller defines a custom resource with the kind `NetworkPolicy` (under the fqdn.konsole.is API group).
To avoid conflicts with the built-in Kubernetes networking.k8s.io/v1 NetworkPolicy, the CRD is registered with:

- Long name: `fqdnnetworkpolicy`
- Short name: `fqdn`

This allows you to interact with the resource easily via kubectl without clashing with the standard resource:

```bash
kubectl get fqdn                   # shorthand
kubectl get fqdnnetworkpolicy     # full resource name
```

Use these when inspecting or managing FQDN-based policies in your cluster.

### Key Fields

| Field                    | Description                                                            |
|--------------------------|------------------------------------------------------------------------|
| `podSelector`            | Selector to match the target pods                                      |
| `egress.toFQDNs`         | List of FQDNs to allow traffic to (max 20 per rule)                    |
| `egress.ports`           | Ports and protocols for each egress rule                               |
| `egress.blockPrivateIPs` | Whether to exclude RFC1918 IPs for the rule (overrides global setting) |
| `ttlSeconds`             | Frequency (in seconds) to re-resolve FQDNs. Default: `60`              |
| `resolveTimeoutSeconds`  | Timeout (in seconds) for DNS lookups. Default: `3`                     |
| `retryTimeoutSeconds`    | Time to keep using stale IPs before dropping them. Default: `3600`     |
| `blockPrivateIPs`        | Whether to exclude private IPs globally                                |
| `enabledNetworkType`     | IP types to allow: `ipv4`, `ipv6`, or `all`. Default: `ipv4`           |

### IP Filtering

Private IPs (RFC1918) can be excluded from resolved FQDN results using the `blockPrivateIPs` setting. This helps enforce 
policies that restrict traffic to public endpoints only.

- The default is `false` (private IPs are allowed).

- Set `spec.blockPrivateIPs: true` to apply filtering to all egress rules by default.

- You can override this behavior on a per-rule basis using `egress[].blockPrivateIPs`.
  If set, this value takes precedence over the global spec.blockPrivateIPs.

### IP Retention on Failure

When FQDN resolution fails, previously resolved IPs are not immediately removed. Instead, they are retained and continue 
to be used in the underlying NetworkPolicy until the `retryTimeoutSeconds` window expires. This ensures that temporary 
DNS issues do not disrupt network access.

#### ✅ IPs are retained for:

- `TIMEOUT`: DNS server did not respond in time

- `TEMPORARY`: A transient network error occurred

- `UNKNOWN`: The controller could not determine the exact error

- `OTHER_ERROR`: Unspecified failure during resolution

#### ❌ IPs are immediately dropped for:

- `INVALID_DOMAIN`: FQDN format is invalid and cannot be resolved

- `NXDOMAIN` (aka DOMAIN_NOT_FOUND): The domain does not exist (permanent failure)

After the retention period (`retryTimeoutSeconds`), the FQDN will be removed from the active policy if resolution has 
not succeeded again.

If you do **not** wish to retain IP addresses for potentially transient resolution failures, you can set 
`retryTimeoutSeconds` to zero.

### Status and Observability

Each FQDN-based NetworkPolicy CR includes detailed status information to help you monitor behavior and troubleshoot 
DNS or policy issues.

#### Key fields in .status:

- `conditions[]`\
   Standard Kubernetes conditions, including:

  - `Ready`: Whether the controller successfully applied the resolved IPs.

  - `Resolve`: Indicates whether the most recent DNS resolution attempt succeeded. Use this to quickly determine the 
     health and reconciliation state of the policy. This is an aggregated summary of all FQDN lookups, surfacing the
     highest measurable error.

- `fqdns[]`\
   Per-FQDN resolution status:

    - `fqdn`: The domain name being resolved.

    - `lastSuccessfulTime`: Timestamp of the most recent successful resolution.

    - `resolveReason`: Result of the most recent DNS attempt (SUCCESS, TIMEOUT, NXDOMAIN, etc.).

    - `resolveMessage`: Human-readable message describing the result.

    - `addresses[]`: The current list of resolved IPs for that FQDN.

   Useful for debugging why traffic is or isn’t allowed, and for verifying DNS behavior.

- `appliedAddressCount`
   Number of unique IPs currently applied to the underlying NetworkPolicy (after filtering, retries, and deduplication).

- `totalAddressesCount`
   Total number of all resolved IPs, including ones filtered out due to blockPrivateIPs or other constraints (after deduplication).

-  `latestLookupTime`
   The last time this policy's FQDNs were resolved. Useful for tracking how fresh the IPs are.

Some of these fields are also surfaced in `kubectl get` for quick inspection:

```bash
kubectl get fqdn networkpolicy-sample
NAME                   READY   RESOLVED   RESOLVED IPs   APPLIED IPs   LAST LOOKUP         AGE
networkpolicy-sample   True    False      5              3             31s                 2m
```

### Custom Resource Example

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

## 🚀 Installation

### Helm installation

If you wish to manage the CRDs outside the helm chart you can install them from the release manifests. You must 
explicitly disable the crd installation in the helm chart if you prefer this, using the flag `--set crd.enable=false`.

```bash
curl -sL https://github.com/konsole-is/fqdn-controller/releases/download/<version>/crds.yaml | kubectl apply -f -
```

Chart installation

```bash
helm repo add fqdn-controller https://konsole-is.github.io/fqdn-controller/charts
helm install fqdn-controller fqdn-controller/fqdn-controller --version <version>
```

### Kubectl installation

```bash
curl -sL https://github.com/konsole-is/fqdn-controller/releases/download/<version>/install.yaml | kubectl apply -f -
```

Note: Will contain only 1 replica unless modified.

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
