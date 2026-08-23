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

## Values

The chart is generated with the Kubebuilder `helm/v2-alpha` plugin. The most important values are:

| Value                   | Default | Description                                                        |
|-------------------------|---------|--------------------------------------------------------------------|
| `manager.image`         |         | Controller image `repository`, `tag` and `pullPolicy`              |
| `manager.args`          |         | Extra arguments passed to the controller manager                   |
| `manager.resources`     |         | Controller container resources                                     |
| `crd.enabled`           | `true`  | Install the CRDs with the chart                                    |
| `crd.keep`              | `true`  | Keep the CRDs when the release is uninstalled                      |
| `webhook.enabled`       | `true`  | Install the admission webhooks (requires cert-manager)             |
| `certManager.enabled`   | `true`  | Create cert-manager `Issuer`/`Certificate` resources               |
| `metrics.enabled`       | `true`  | Expose the metrics endpoint                                        |
| `prometheus.enabled`    | `false` | Create a `ServiceMonitor` (requires the Prometheus Operator CRDs)  |
| `networkPolicy.enabled` | `false` | Create `NetworkPolicy` resources for the controller                |
| `rbac.helpers.enabled`  | `false` | Install the admin/editor/viewer `ClusterRole`s for the CRD         |

See `values.yaml` in the chart for the full list.

### Upgrading from charts generated with `helm/v1-alpha`

Chart versions that were generated with the deprecated `helm/v1-alpha` plugin used different value names. When
upgrading, rename the following values:

| Old value                    | New value               |
|------------------------------|-------------------------|
| `controllerManager.*`        | `manager.*`             |
| `controllerManager.container.image` | `manager.image`  |
| `crd.enable`                 | `crd.enabled`           |
| `webhook.enable`             | `webhook.enabled`       |
| `certmanager.enable`         | `certManager.enabled`   |
| `metrics.enable`             | `metrics.enabled`       |
| `prometheus.enable`          | `prometheus.enabled`    |
| `networkPolicy.enable`       | `networkPolicy.enabled` |
| `rbac.enable`                | removed (RBAC is always installed; see `rbac.namespaced` and `rbac.helpers.enabled`) |

## Verifying chart signatures

All charts are signed using GPG. You can verify the authenticity and integrity of a chart using the .prov file and the 
public GPG key.

```helm
gpg --keyserver hkps://keys.openpgp.org --recv-keys 6D2CDAA28E7B8D360B8C63817D7F57D9C5527906
helm pull konsole/fqdn-controller --version <version> --verify
```