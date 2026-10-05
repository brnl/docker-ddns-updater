# docker-ddns-updater

A secure Docker image and Kubernetes Helm chart that actively monitors your
external IP address and updates supported DDNS providers when it changes.

Supported providers:

| Provider | `DDNS_PROVIDER` | IPv4 | IPv6 |
| -------- | --------------- | ---- | ---- |
| [mijn.host](https://mijn.host) | `mijnhost` | ✅ | ✅ |

## Features

- Checks the public IP every minute (configurable) using
  [ipify](https://www.ipify.org) and [ifconfig.me](https://ifconfig.me).
- IPv4 and IPv6 are both optional and can be enabled independently.
- Only calls the provider when something changed: the detected IP is compared
  with the published DNS record at startup and periodically, and with the
  last successful update in between.
- **Cross-checks IP sources.** All sources are queried in parallel and must
  agree; a single faulty or compromised source cannot redirect your DNS.
- Backs off exponentially on errors, and for an hour on permanent errors such
  as bad credentials or an unknown hostname, so you won't be flagged for abuse.
- Ignores split-horizon DNS answers: only public addresses count as the
  published record.
- A built-in **status page**, Prometheus **metrics** with an optional
  ServiceMonitor and alerting rules, and `/healthz`, `/readyz` and
  `/status.json`.
- A small, hardened image (~21 MB): a static Go 1.27 binary with no third-party
  dependencies on [distroless](https://github.com/GoogleContainerTools/distroless),
  with no shell. It runs as non-root on a read-only root filesystem with no
  capabilities. Released images are multi-arch (amd64, arm64, armv7), signed
  with cosign, and published with an SBOM and provenance.

## Quick start (Docker)

```sh
docker run -d --name ddns-updater --restart unless-stopped \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  -p 127.0.0.1:8080:8080 \
  -e DDNS_HOSTNAMES=home.example.com \
  -e DDNS_USERNAME=your-dyndns-username \
  -e DDNS_PASSWORD=your-dyndns-password \
  ghcr.io/brnl/docker-ddns-updater:latest
```

Then open <http://127.0.0.1:8080/> to see the status page.

### Docker Compose

```yaml
services:
  ddns-updater:
    image: ghcr.io/brnl/docker-ddns-updater:latest
    restart: unless-stopped
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    ports:
      - 127.0.0.1:8080:8080
    environment:
      DDNS_HOSTNAMES: home.example.com,vpn.example.com
      DDNS_IPV6_ENABLED: "true"
      DDNS_USERNAME_FILE: /run/secrets/ddns_username
      DDNS_PASSWORD_FILE: /run/secrets/ddns_password
    secrets: [ddns_username, ddns_password]

secrets:
  ddns_username:
    file: ./secrets/username
  ddns_password:
    file: ./secrets/password
```

For IPv6, the container needs global IPv6 connectivity. Either enable IPv6 on
the Docker network or use `network_mode: host`.

## Kubernetes (Helm)

```sh
kubectl create secret generic ddns-updater \
  --from-literal=username=your-dyndns-username \
  --from-literal=password=your-dyndns-password

helm install ddns-updater oci://ghcr.io/brnl/charts/ddns-updater \
  --set hostnames[0]=home.example.com \
  --set credentials.existingSecret=ddns-updater
```

From a checkout, use `charts/ddns-updater` instead of the OCI reference.

Notable values (see [`values.yaml`](charts/ddns-updater/values.yaml) for all):

| Value | Default | Description |
| ----- | ------- | ----------- |
| `hostnames` | `[]` | Hostnames to update (required) |
| `credentials.existingSecret` | `""` | Existing Secret with `username`/`password` keys (recommended) |
| `credentials.username` / `.password` | `""` | Or let the chart create the Secret |
| `externalSecret.enabled` | `false` | Let External Secrets Operator create the Secret (see below) |
| `extraObjects` | `[]` | Extra manifests to deploy with the release (see below) |
| `ipv4.enabled` / `ipv6.enabled` | `true` / `false` | Address families to manage |
| `interval` | `60s` | How often to check the public IP |
| `dnsRecheckInterval` | `5m` | How often to compare with the published DNS record |
| `dnsServer` | `""` | DNS server for record lookups; set it with split-horizon DNS (see below) |
| `hostNetwork` | `false` | Use the node's network (see below) |
| `statusPage.enabled` | `true` | Serve the status page |
| `metrics.enabled` | `true` | Serve Prometheus metrics on `/metrics` |
| `metrics.serviceMonitor.enabled` / `metrics.prometheusRule.enabled` | `false` | Prometheus Operator resources (see below) |
| `ingress.enabled` | `false` | Expose the status page through an Ingress |
| `httpRoute.enabled` | `false` | Expose the status page through a Gateway API HTTPRoute (`httpRoute.parentRefs` required) |
| `networkPolicy.enabled` | `false` | Allow only DNS and HTTPS egress, and ingress from `networkPolicy.ingressFrom` |

The values are validated against a strict schema, so a typo such as
`dnsserver:` fails the install instead of being silently ignored.

The chart always runs a single replica with the `Recreate` strategy, because
concurrent updaters would race each other. Credentials are mounted as files,
not exposed as environment variables. No service account token is mounted. Pods
use the `restricted` Pod Security Standard settings: non-root, read-only root
filesystem, all capabilities dropped and the `RuntimeDefault` seccomp profile.

**IPv6 on Kubernetes:** the pod detects the address its own traffic leaves
from. If pods have no global IPv6 egress, or their egress is NATed to an
address other than the one you want published, set `hostNetwork: true`.

### External Secrets Operator

Instead of creating the Secret yourself, the chart can render an
[`ExternalSecret`](https://external-secrets.io) that syncs the credentials from
your secret backend (Vault, 1Password, AWS/GCP/Azure secret managers, ...):

```yaml
externalSecret:
  enabled: true
  secretStoreRef:
    kind: ClusterSecretStore
    name: my-store
  username:
    key: ddns/mijnhost
    property: username
  password:
    key: ddns/mijnhost
    property: password
```

The credentials are read at startup. When the ExternalSecret spec changes the
pod restarts automatically. To also pick up rotated values from the backend,
use a tool such as [Reloader](https://github.com/stakater/Reloader) through
`podAnnotations`.

### Extra manifests

`extraObjects` deploys arbitrary additional manifests with the release, for
example a `SecretStore`, a `PodDisruptionBudget` or a `ServiceMonitor`. Items
may be objects or YAML strings, and are rendered with `tpl`:

```yaml
extraObjects:
  - apiVersion: v1
    kind: ConfigMap
    metadata:
      name: '{{ include "ddns-updater.fullname" . }}-extra'
    data:
      release: "{{ .Release.Name }}"
```

### Monitoring

The app serves Prometheus metrics on `/metrics`. With the Prometheus Operator
(for example kube-prometheus-stack), enable the ServiceMonitor and the alerting
rules:

```yaml
metrics:
  serviceMonitor:
    enabled: true
    labels:
      release: kube-prometheus-stack # only if your Prometheus selects on it
  prometheusRule:
    enabled: true
```

The built-in alerts are:

| Alert | Fires when |
| ----- | ---------- |
| `DDNSUpdaterDown` | the pod cannot be scraped for 10 minutes |
| `DDNSUpdaterHostOutOfSync` | a record has not matched the public IP for `outOfSyncFor` (30m), e.g. because updates keep failing |
| `DDNSUpdaterIPDetectionFailing` | the public IP could not be determined for `detectionFailingFor` (15m) |
| `DDNSUpdaterSplitHorizonDNS` | DNS lookups return only internal addresses for an hour (info) |

Add your own rules with `metrics.prometheusRule.additionalRules`. With
`networkPolicy.enabled`, add Prometheus to `networkPolicy.ingressFrom`.

The readiness probe deliberately uses `/healthz`, so the status page stays
reachable while updates fail. Use the metrics and alerts above, or `/readyz`,
to detect failing updates.

### Split-horizon DNS

If the cluster resolves your hostnames to internal addresses (split-horizon
DNS), those answers say nothing about the public record. The updater ignores
DNS answers that contain only non-public addresses, logs a warning and shows
it on the status page. Point `dnsServer` at a public resolver so the record can
be verified:

```yaml
dnsServer: 1.1.1.1 # or a hostname such as dns.quad9.net, optionally with :port
```

## Configuration

All settings are environment variables.

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `DDNS_PROVIDER` | `mijnhost` | DDNS provider |
| `DDNS_HOSTNAMES` | — | Comma-separated hostnames to update (required) |
| `DDNS_USERNAME` / `DDNS_USERNAME_FILE` | — | DynDNS username, or a file containing it (required) |
| `DDNS_PASSWORD` / `DDNS_PASSWORD_FILE` | — | DynDNS password, or a file containing it (required) |
| `DDNS_IPV4_ENABLED` | `true` | Manage the A record |
| `DDNS_IPV6_ENABLED` | `false` | Manage the AAAA record |
| `DDNS_IPV4_SOURCES` | `https://api.ipify.org,https://ifconfig.me/ip` | Plain-text IPv4 sources |
| `DDNS_IPV6_SOURCES` | `https://api6.ipify.org,https://ifconfig.me/ip` | Plain-text IPv6 sources |
| `DDNS_INTERVAL` | `60s` | Check interval (`30`, `30s`, `1m`, ...). Each check queries every source, so don't go much lower than 30s |
| `DDNS_TIMEOUT` | `10s` | Timeout per HTTP request |
| `DDNS_DNS_RECHECK_INTERVAL` | `5m` | How often to compare with the published DNS record (`0` = only at startup) |
| `DDNS_DNS_SERVER` | system resolver | DNS server for record lookups: an IP address or hostname with an optional port, e.g. `1.1.1.1`, `dns.quad9.net` or `[2606:4700:4700::1111]:53` |
| `DDNS_DRY_RUN` | `false` | Log what would be updated without calling the provider |
| `DDNS_LISTEN_ADDR` | `:8080` | Address for the status page and health endpoints (`off` disables it) |
| `DDNS_STATUS_PAGE` | `true` | Serve the status page on `/` and `/status.json` |
| `DDNS_METRICS` | `true` | Serve Prometheus metrics on `/metrics` |
| `DDNS_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error` |
| `DDNS_LOG_FORMAT` | `json` | `json` or `text` |

## How it works

On every interval, for each enabled family:

1. Query all IP sources in parallel, over that address family only (IPv4
   requests are dialled over IPv4, IPv6 requests over IPv6). Proxies are
   deliberately bypassed. A result is accepted only if every source that
   answered returned the same public (globally routable) address.
2. For each hostname, compare the address with the last known record. The
   last known record comes from a DNS lookup at startup and every
   `DDNS_DNS_RECHECK_INTERVAL`, and from each successful update. DNS answers
   that contain only non-public addresses (split-horizon DNS) are ignored.
3. If anything differs, send one update containing every detected family.

### mijn.host

Updates use the mijn.host DynDNS endpoint:

```
https://mijn.host/nic/update?hostname=<hostname>&myip=<ipv4>&myipv6=<ipv6>
```

Credentials are sent with HTTP Basic authentication in a header, never in the
URL, and redirects are never followed. If a family is disabled or could not
be detected, that parameter is left out. When no address could be detected at
all, no request is sent, because mijn.host would otherwise fall back to the
request's source address. The dyndns2 responses `good` and `nochg` count as
success. `badauth`, `nohost`, `notfqdn` and `abuse` are permanent errors and
pause updates for that hostname for an hour. `911` and `dnserr` are retried
with exponential backoff.

## Status page and endpoints

`GET /` shows the detected public IPs, the state of each hostname, the last
error and the configuration. It is a single server-rendered HTML page with no
JavaScript and no external resources, and it is served with a strict
Content-Security-Policy. It never shows credentials, but it does reveal your
public IP and hostnames, so don't expose it publicly without authentication.
Set `DDNS_STATUS_PAGE=false` to serve only the health and metrics endpoints.

| Endpoint | Description |
| -------- | ----------- |
| `/` | Status page (auto-refreshes) |
| `/status.json` | The same data as JSON |
| `/metrics` | Prometheus metrics |
| `/healthz` | Liveness: the check loop is running |
| `/readyz` | Readiness: the last check cycle fully succeeded |

The image's Docker `HEALTHCHECK` runs `/ddns-updater healthcheck`, since there
is no shell or curl in the image.

## Development

```sh
go test -race ./...
docker build -t ddns-updater:dev .
helm lint --strict charts/ddns-updater -f charts/ddns-updater/ci/all-features-values.yaml
```

## Releasing

`version` in [`Chart.yaml`](charts/ddns-updater/Chart.yaml) is the single
source of truth for the chart version, the image tag and the git tag, and
`appVersion` must equal it (CI enforces both). To release, bump both in a pull
request following [semantic versioning](https://semver.org). When it is merged
into `main`, the release workflow:

1. publishes the image as `X.Y.Z`, `X.Y`, `X` and `latest` (plus `edge`),
   signed with cosign;
2. publishes the signed chart to `oci://ghcr.io/brnl/charts/ddns-updater`;
3. tags the commit `vX.Y.Z` and creates a GitHub release.

Don't create tags by hand. Pushes to `main` that don't change the version only
publish the `edge` image.
