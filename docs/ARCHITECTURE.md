# Homelab Kubernetes Architecture

## Overview

Production-grade Kubernetes homelab running on bare-metal with kubeadm, managed via GitOps (ArgoCD App-of-Apps pattern). All cluster configuration lives in this repository and is automatically synced by ArgoCD.

**Cluster**: Kubernetes v1.30.14 | **CNI**: Cilium 1.19.1 | **Runtime**: containerd 1.7.8 | **OS**: Ubuntu 24.04.4 LTS

```
                         ┌─────────────────────────────────────────────────┐
                         │              CLOUDFLARE EDGE                    │
                         │                                                 │
                         │  *.racktocloud.com ──► Cloudflare Tunnel        │
                         │  (DNS + Proxy)         "homelab-k8s"            │
                         │                            │                    │
                         │  Cloudflare Access ────────┤ (Service Auth)     │
                         │  (ai.racktocloud.com)      │                    │
                         └────────────────────────────┼────────────────────┘
                                                      │
                    ┌─────────────────────────────────┼──────────────────────────────┐
                    │            HOME NETWORK (10.0.0.0/24)                          │
                    │                                 │                              │
                    │                                 ▼                              │
                    │  ┌──────────────────────────────────────────────────────────┐   │
                    │  │              KUBERNETES CLUSTER                          │   │
                    │  │                                                          │   │
                    │  │  ┌─────────────┐  ┌─────────────┐                       │   │
                    │  │  │ infmk8s-n01 │  │ infmk8s-n02 │  Control Plane (HA)   │   │
                    │  │  │ 10.0.0.100  │  │ 10.0.0.101  │  etcd, api-server,    │   │
                    │  │  │ CP + etcd   │  │ CP + etcd   │  scheduler, ctrl-mgr  │   │
                    │  │  └─────────────┘  └─────────────┘                       │   │
                    │  │                                                          │   │
                    │  │  ┌─────────────┐  ┌─────────────┐                       │   │
                    │  │  │ infwk8s-n01 │  │ infwk8s-n02 │  Workers              │   │
                    │  │  │ 10.0.0.102  │  │ 10.0.0.103  │  (workloads run here) │   │
                    │  │  │ NVIDIA GPU  │  │             │                       │   │
                    │  │  └─────────────┘  └─────────────┘                       │   │
                    │  │                                                          │   │
                    │  │  MetalLB L2 Pool: 10.0.0.150 - 10.0.0.200               │   │
                    │  └──────────────────────────────────────────────────────────┘   │
                    │                                                                │
                    │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
                    │  │  NFS Server  │  │ DGX Spark 1  │  │ DGX Spark 2  │          │
                    │  │  10.0.0.16   │  │  (Ollama)    │  │ (available)  │          │
                    │  │              │  │  qwen3:30b   │  │              │          │
                    │  └──────────────┘  └──────────────┘  └──────────────┘          │
                    └────────────────────────────────────────────────────────────────┘
```

## Nodes

| Hostname | IP | Role | Notes |
|---|---|---|---|
| infmk8s-n01 | 10.0.0.100 | control-plane | etcd member, kube-apiserver |
| infmk8s-n02 | 10.0.0.101 | control-plane | etcd member, kube-apiserver |
| infwk8s-n01 | 10.0.0.102 | worker | NVIDIA GPU (gpu-operator managed) |
| infwk8s-n02 | 10.0.0.103 | worker | Primary workload node |

## GitOps Model

```
  github.com/ahpythoneer/kubernetes-config (PUBLIC)
                    │
                    ▼
        ┌───────────────────┐
        │  ArgoCD v3.3.2    │
        │  App-of-Apps      │
        └────────┬──────────┘
                 │
        ┌────────┴────────────────────────────────────────────┐
        │                                                      │
        ▼                                                      ▼
  "infrastructure" App                               Helm-based ArgoCD Apps
  (kustomization.yaml)                               (Application CRDs)
        │                                                      │
        ├── Raw manifests:                                     ├── cert-manager v1.13.0
        │   alertmanager, prometheus,                          ├── ingress-nginx 4.14.3
        │   grafana, heimdall, code-server,                    ├── metallb 0.15.3
        │   cloudflared, unifi, ollama,                        ├── vault 0.27.0
        │   joplin, vaultwarden,                               ├── harbor 1.16.2
        │   browser-service, research-worker,                  ├── loki 6.30.1
        │   monitoring/node-exporter                           ├── alloy 0.12.5
        │                                                      ├── external-dns 1.15.1
        └── Namespace + Application CRDs                       └── kured 5.6.0
            (for Helm apps above)
```

**Repository is PUBLIC** — never commit secrets. All sensitive values are managed as:
- Vault KV secrets (injected via agent sidecar)
- Out-of-band Kubernetes Secrets (created manually, not in git)

## Networking

### Traffic Flow

```
  EXTERNAL USERS                    LOCAL NETWORK
       │                                 │
       ▼                                 │
  Cloudflare Tunnel ──────┐              │
  (2 replicas)            │              │
       │                  │              │
       ▼                  ▼              ▼
  ┌─────────────────────────────────────────┐
  │  NGINX Ingress Controller               │
  │  LoadBalancer: 10.0.0.150               │
  │  (use-forwarded-headers: true)          │
  │                                         │
  │  Routes:                                │
  │  ├── argocd.racktocloud.com     → :443  │  (backend-protocol: HTTPS)
  │  ├── code.racktocloud.com       → :80   │
  │  ├── grafana.racktocloud.com    → :80   │
  │  ├── harbor.racktocloud.com     → :80   │
  │  ├── heimdall.racktocloud.com   → :80   │
  │  ├── joplin.racktocloud.com     → :22300│
  │  ├── prometheus.racktocloud.com → :80   │
  │  └── k8vault.racktocloud.com    → :80   │  (Vaultwarden)
  └─────────────────────────────────────────┘

  DIRECT LoadBalancer ACCESS (no ingress):
  ├── 10.0.0.152  Vault        :8200
  ├── 10.0.0.164  Ollama       :11434
  └── 10.0.0.165  UniFi        :8443,:8080,:3478,:10001,:1900
```

### Cloudflare Tunnel Routes

The tunnel "homelab-k8s" is **remotely managed** (routes configured in Cloudflare dashboard, not in-cluster). Known routes:

| Public Hostname | Backend Service |
|---|---|
| harbor.racktocloud.com | ingress-nginx (10.0.0.150) |
| joplin.racktocloud.com | ingress-nginx (10.0.0.150) |
| k8vault.racktocloud.com | ingress-nginx (10.0.0.150) |
| ai.racktocloud.com | ollama LB (10.0.0.164:11434) |

`ai.racktocloud.com` is protected by **Cloudflare Access** (Service Auth policy) requiring `CF-Access-Client-Id` and `CF-Access-Client-Secret` headers.

### DNS

- **external-dns** manages A/CNAME records for `racktocloud.com` in Cloudflare
- Policy: `upsert-only` (never deletes records)
- TXT ownership prefix: `_externaldns.`
- All ingress records are Cloudflare-proxied (`--cloudflare-proxied`)

### TLS

- **cert-manager** with `letsencrypt-prod` ClusterIssuer
- Solvers: DNS-01 (Cloudflare API token) + HTTP-01 (nginx ingress)
- All 8 ingress hosts have auto-renewed Let's Encrypt certificates

### Remote Access

- **Cloudflare Tunnel**: External access to web services (harbor, joplin, vaultwarden, ollama API)
- **Twingate**: Zero-trust VPN connector ("pumpkin-marmoset") for internal network access

### MetalLB

L2 advertisement mode. IP pool: `10.0.0.150-10.0.0.200` (51 IPs, 4 assigned, 47 available).

## Storage

### NFS (Default Storage Class)

| Parameter | Value |
|---|---|
| Provisioner | nfs-subdir-external-provisioner v4.0.2 |
| Server | 10.0.0.16 |
| Base Path | /mnt/Share/INF-K8s-NFS01 |
| Path Pattern | `{namespace}-{pvc-name}` |
| Reclaim Policy | Delete (archiveOnDelete: true) |
| Volume Binding | Immediate |

**Note**: NFS server uses `root_squash`. Containers requiring root init (e.g., linuxserver.io images) need initContainers running as the target UID to pre-create directory structures.

### Persistent Volume Claims

| Namespace | PVC | Size | Purpose |
|---|---|---|---|
| alertmanager | alertmanager-storage | 2Gi | Alert data |
| code-server | code-server-storage | 20Gi | Workspace |
| databases | data-postgresql-0 | 10Gi | Shared PostgreSQL |
| grafana | grafana-storage | 5Gi | Dashboards, config |
| harbor | harbor-registry | 50Gi | Container images |
| harbor | database-data-harbor-database-0 | 5Gi | Harbor DB |
| harbor | data-harbor-redis-0 | 2Gi | Harbor cache |
| harbor | data-harbor-trivy-0 | 5Gi | Vulnerability DB |
| harbor | harbor-jobservice | 1Gi | Job logs |
| heimdall | heimdall-storage | 5Gi | Dashboard config |
| loki | storage-loki-0 | 20Gi | Log storage |
| ollama | ollama-models | 100Gi | LLM model weights |
| prometheus | prometheus-storage | 20Gi | Metrics TSDB |
| unifi | unifi-data | 5Gi | Network controller |
| vault | data-vault-0 | 20Gi | Secrets engine |
| vaultwarden | vaultwarden-storage | 10Gi | Password vault |

**Total NFS**: ~270Gi across 16 PVCs

Longhorn is installed but not actively used as primary storage.

## Secrets Management

### HashiCorp Vault

- **Version**: Helm chart 0.27.0
- **Seal**: Shamir 5/3 (5 key shares, 3 required to unseal)
- **Auth**: Kubernetes auth method (ServiceAccount-based)
- **Injector**: Vault Agent sidecar injects secrets as files into pods

Services using Vault agent injection:
- **Joplin** — PostgreSQL credentials (`secret/data/joplin/database`)
- **Grafana** — Admin password (`secret/data/grafana`)
- **Heimdall** — Admin password (`secret/data/heimdall`)
- **Code Server** — Access password (`secret/data/code-server`)
- **Vaultwarden** — Admin token (`secret/data/vaultwarden`)
- **Browser Service** — Config (`secret/data/browser-service`)
- **Prometheus** — Config (`secret/data/prometheus`)
- **Ollama** — Config (`secret/data/ollama`)

### Out-of-Band Kubernetes Secrets

These secrets are created manually and NOT stored in git:

| Namespace | Secret Name | Purpose |
|---|---|---|
| cert-manager | cloudflare-api-token | DNS-01 challenge + external-dns |
| cloudflared | cloudflared-tunnel-token | Tunnel authentication |
| harbor | harbor-admin-secret | Admin password |
| harbor | harbor-core-secret | Core encryption key |
| alertmanager | telegram-bot-token | AlertManager Telegram notifications |
| default | twingate-magic-lemur-connector | Twingate VPN tokens |
| external-dns | cloudflare-api-token | Cloudflare API access |

## Observability Stack

```
  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
  │ Node Exporter│     │   Alloy      │     │  Prometheus  │
  │ (DaemonSet)  │     │ (DaemonSet)  │     │              │
  │ 4 nodes      │     │ 2 workers    │     │  Scrapes:    │
  │              │     │              │     │  - nodes     │
  │  Exports:    │     │  Collects:   │     │  - pods      │
  │  - CPU       │     │  - Pod logs  │     │  - services  │
  │  - Memory    │     │  - K8s events│     │              │
  │  - Disk      │     │              │     │  Alert Rules:│
  │  - Network   │     │      │       │     │  - NodeDown  │
  └──────┬───────┘     │      │       │     │  - PodCrash  │
         │             │      ▼       │     └──────┬───────┘
         │             │  ┌────────┐  │            │
         │             │  │  Loki  │  │            ▼
         │             │  │ Single │  │     ┌──────────────┐
         │             │  │ Binary │  │     │ AlertManager │
         │             │  │ 31-day │  │     │  v0.27.0     │
         │             │  │retention│ │     │              │
         │             │  └────┬───┘  │     │  Telegram    │
         │             └──────┼──────┘     │  Notifications│
         │                    │            └──────────────┘
         │                    │
         ▼                    ▼
  ┌─────────────────────────────────┐
  │           Grafana               │
  │  Datasources:                   │
  │  - Prometheus (metrics)         │
  │  - Loki (logs)                  │
  └─────────────────────────────────┘
```

## Service Catalog

### Platform Services

| Service | Namespace | Type | Version | Purpose |
|---|---|---|---|---|
| ArgoCD | argocd | Helm (manual) | v3.3.2 | GitOps continuous delivery |
| cert-manager | cert-manager | Helm (ArgoCD) | v1.13.0 | TLS certificate automation |
| Ingress NGINX | ingress-nginx | Helm (ArgoCD) | 1.14.3 | Ingress controller |
| MetalLB | metallb-system | Helm (ArgoCD) | 0.15.3 | Bare-metal load balancer |
| Cilium | kube-system | Helm (manual) | 1.19.1 | CNI + network policy + Hubble |
| NFS Provisioner | kube-system | Helm (manual) | 4.0.18 | Dynamic NFS PV provisioner |
| external-dns | external-dns | Helm (ArgoCD) | 1.15.1 | Automatic DNS management |
| kured | kured | Helm (ArgoCD) | 5.6.0 | Automated OS reboot scheduling |
| Cloudflared | cloudflared | Raw manifest | 2024.12.2 | Cloudflare Tunnel connector |
| Twingate | default | Helm (manual) | 0.1.33 | Zero-trust VPN connector |

### Observability

| Service | Namespace | Type | Version | Purpose |
|---|---|---|---|---|
| Prometheus | prometheus | Raw manifest | latest | Metrics collection |
| Grafana | grafana | Raw manifest | latest | Dashboards & visualization |
| Loki | loki | Helm (ArgoCD) | 6.30.1 | Log aggregation |
| Alloy | alloy | Helm (ArgoCD) | 0.12.5 | Log collection agent |
| AlertManager | alertmanager | Raw manifest | v0.27.0 | Alert routing (Telegram) |
| Node Exporter | monitoring | Raw manifest | latest | Node-level metrics |
| NVIDIA DCGM | gpu-operator | Helm (manual) | v25.10.1 | GPU metrics |

### Application Services

| Service | Namespace | Type | Version | Purpose |
|---|---|---|---|---|
| Vault | vault | Helm (ArgoCD) | 0.27.0 | Secrets management |
| Harbor | harbor | Helm (ArgoCD) | 1.16.2 (v2.12.2) | Container registry |
| Joplin | joplin | Raw manifest | latest | Note-taking server |
| Vaultwarden | vaultwarden | Raw manifest | latest | Password manager |
| Heimdall | heimdall | Raw manifest | latest | Application dashboard |
| Code Server | code-server | Raw manifest | latest | Web-based IDE |
| Ollama | ollama | Raw manifest | latest | LLM inference API |
| UniFi | unifi | Raw manifest | v8.6 | Network controller |
| PostgreSQL | databases | Helm (manual) | 18.3.0 | Shared database |
| Browser Service | browser-service | Raw manifest | latest | Headless Chrome |
| Research Worker | research-worker | Raw manifest | CronJob | Automated note enhancement |

### GPU Stack

NVIDIA GPU Operator (v25.10.1) manages the GPU on `infwk8s-n01`:
- Device Plugin DaemonSet
- Container Toolkit DaemonSet
- DCGM Exporter (metrics on :9400)
- GPU Feature Discovery
- Operator Validator

### External Devices

| Device | IP/Location | Purpose |
|---|---|---|
| NFS Server | 10.0.0.16 | Persistent volume storage |
| DGX Spark 1 | LAN | Ollama (qwen3:30b-a3b, ~94 tok/s) |
| DGX Spark 2 | LAN | Available, not configured |

## Maintenance

### kured (Kubernetes Reboot Daemon)

- **Schedule**: Sundays 3:00-6:00 AM CT
- **Concurrency**: 1 node at a time
- **Coverage**: All 4 nodes (tolerates control-plane taint)
- **Trigger**: Checks `/var/run/reboot-required` (set by unattended-upgrades)

### GitHub Actions

- `.github/workflows/secret-scan.yml` — Pre-push secret scanning to prevent credential leaks in the public repo
