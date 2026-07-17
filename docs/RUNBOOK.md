# Operational Runbook

## Cold-Start Procedure

After a full cluster power-off, services must be brought up in dependency order. Kubernetes control plane components (etcd, kube-apiserver, kube-scheduler, kube-controller-manager) start automatically via kubelet static pods.

### Boot Order

```
1. NFS Server (10.0.0.16)           ← PVCs depend on this
2. Control plane nodes               ← kubelet starts static pods automatically
   infmk8s-n01 (10.0.0.100)
   infmk8s-n02 (10.0.0.101)
3. Worker nodes                      ← workloads scheduled here
   infwk8s-n01 (10.0.0.102)
   infwk8s-n02 (10.0.0.103)
4. Unseal Vault                      ← secrets injection depends on this
5. Verify ArgoCD                     ← will auto-sync all apps
6. DGX Spark 1                       ← Ollama (independent, not in cluster)
```

### Step-by-Step

**1. Verify nodes are Ready:**
```bash
kubectl get nodes
```
All 4 nodes should show `Ready`. If a node is `NotReady`, check kubelet:
```bash
ssh 10.0.0.10X
sudo systemctl status kubelet
sudo journalctl -u kubelet --tail=50
```

**2. Verify NFS is accessible:**
```bash
kubectl get pvc --all-namespaces | grep -v Bound
```
All PVCs should be `Bound`. If any show `Pending`, check NFS server connectivity:
```bash
showmount -e 10.0.0.16
```

**3. Unseal Vault (REQUIRED after every restart):**

Vault uses Shamir 5/3 sealing — 3 of 5 unseal keys are needed.

```bash
# Check seal status
kubectl exec -n vault vault-0 -- vault status

# If sealed, provide 3 keys (one at a time)
kubectl exec -n vault vault-0 -- vault operator unseal <KEY_1>
kubectl exec -n vault vault-0 -- vault operator unseal <KEY_2>
kubectl exec -n vault vault-0 -- vault operator unseal <KEY_3>
```

The 5 unseal keys are stored offline. After unsealing, verify:
```bash
kubectl exec -n vault vault-0 -- vault status
# Sealed: false
# HA Mode: standalone
```

**4. Restart Vault-dependent pods:**

After Vault unseals, pods with Vault agent sidecars may need a restart if they started before Vault was available:

```bash
# Check for pods stuck in Init
kubectl get pods --all-namespaces | grep -E "Init|Error"

# Restart affected deployments
kubectl rollout restart deploy/joplin-server -n joplin
kubectl rollout restart deploy/grafana -n grafana
kubectl rollout restart deploy/heimdall -n heimdall
kubectl rollout restart deploy/code-server -n code-server
kubectl rollout restart deploy/vaultwarden -n vaultwarden
kubectl rollout restart deploy/prometheus -n prometheus
kubectl rollout restart deploy/ollama -n ollama
kubectl rollout restart deploy/browser-service -n browser-service
```

**5. Verify ArgoCD sync:**
```bash
kubectl get app -n argocd
```
All apps should show `Synced`. If any show `OutOfSync`, ArgoCD's auto-sync will reconcile within 3 minutes.

**6. Verify external access:**
```bash
# Cloudflare Tunnel
kubectl get pods -n cloudflared
kubectl logs -n cloudflared -l app=cloudflared --tail=5

# Twingate
kubectl logs deploy/twingate-magic-lemur-connector -n default --tail=5
# Should show "State: Online"
```

## Secret Rotation

### Vault Unseal Keys

Keys are Shamir 5/3. To re-key (e.g., if a key is compromised):

```bash
kubectl exec -n vault vault-0 -- vault operator rekey -init -key-shares=5 -key-threshold=3
# Provide 3 existing keys, then receive 5 new keys
kubectl exec -n vault vault-0 -- vault operator rekey -nonce=<NONCE> <OLD_KEY>
# Repeat for 3 keys total
```

### Cloudflare API Token

Used by cert-manager (DNS-01) and external-dns. Update in both namespaces:
```bash
kubectl create secret generic cloudflare-api-token \
  -n cert-manager \
  --from-literal=api-token=<NEW_TOKEN> \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl create secret generic cloudflare-api-token \
  -n external-dns \
  --from-literal=api-token=<NEW_TOKEN> \
  --dry-run=client -o yaml | kubectl apply -f -
```

### Twingate Connector Tokens

Generate new tokens in Twingate admin panel, then:
```bash
kubectl create secret generic twingate-magic-lemur-connector \
  -n default \
  --from-literal=TWINGATE_ACCESS_TOKEN=<TOKEN> \
  --from-literal=TWINGATE_REFRESH_TOKEN=<TOKEN> \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl rollout restart deploy/twingate-magic-lemur-connector -n default
```

### Cloudflare Tunnel Token

Generate a new token in the Cloudflare Zero Trust dashboard under Networks > Tunnels:
```bash
kubectl create secret generic cloudflared-tunnel-token \
  -n cloudflared \
  --from-literal=token=<NEW_TOKEN> \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl rollout restart deploy/cloudflared -n cloudflared
```

## Common Operations

### Adding a New Ingress Service

1. Create the ingress manifest:
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: my-service
  namespace: my-namespace
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - my-service.racktocloud.com
    secretName: my-service-tls
  rules:
  - host: my-service.racktocloud.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: my-service
            port:
              number: 80
```

2. Add to `kustomization.yaml`
3. Commit and push — ArgoCD auto-syncs
4. external-dns creates DNS record in Cloudflare automatically
5. cert-manager provisions TLS certificate automatically

### Adding a Vault Secret for a Service

1. Write the secret to Vault:
```bash
kubectl exec -n vault vault-0 -- vault kv put secret/my-service/config \
  key1=value1 key2=value2
```

2. Create a Vault policy:
```bash
kubectl exec -n vault vault-0 -- vault policy write my-service - <<EOF
path "secret/data/my-service/*" {
  capabilities = ["read"]
}
EOF
```

3. Create a Kubernetes auth role:
```bash
kubectl exec -n vault vault-0 -- vault write auth/kubernetes/role/my-service \
  bound_service_account_names=my-service \
  bound_service_account_namespaces=my-namespace \
  policies=my-service \
  ttl=1h
```

4. Add Vault annotations to the pod spec:
```yaml
annotations:
  vault.hashicorp.com/agent-inject: "true"
  vault.hashicorp.com/role: "my-service"
  vault.hashicorp.com/agent-inject-secret-config: "secret/data/my-service/config"
  vault.hashicorp.com/agent-inject-template-config: |
    {{- with secret "secret/data/my-service/config" -}}
    export KEY1="{{ .Data.data.key1 }}"
    export KEY2="{{ .Data.data.key2 }}"
    {{- end }}
```

### Checking Logs (Grafana/Loki)

Access Grafana at `grafana.racktocloud.com` and use the Explore view with Loki datasource.

Useful LogQL queries:
```
# All logs from a namespace
{namespace="joplin"}

# Errors across the cluster
{cluster="homelab"} |= "error" != "metrics"

# Specific pod logs
{namespace="vault", pod=~"vault-0.*"}

# Kubernetes events
{job="integrations/kubernetes/eventhandler"}
```

Or query Loki directly:
```bash
kubectl exec -n loki loki-0 -- wget -qO- \
  'http://localhost:3100/loki/api/v1/query?query={namespace="joplin"}&limit=10'
```

### Monitoring Alerts

AlertManager sends notifications to Telegram (chat ID: 1075093819). Current alert rules:

| Alert | Condition | Severity |
|---|---|---|
| NodeDown | Node unreachable for 2 minutes | critical |
| PodCrashLooping | Pod restarted >3 times in 15 minutes | warning |

To test alerting:
```bash
curl -XPOST http://alertmanager.alertmanager.svc.cluster.local:9093/api/v1/alerts \
  -H "Content-Type: application/json" \
  -d '[{"labels":{"alertname":"TestAlert","severity":"info"},"annotations":{"summary":"Test notification"}}]'
```

### NFS Permissions (linuxserver.io Images)

NFS `root_squash` prevents root from modifying files. For linuxserver.io containers that need root init (s6-overlay), add an initContainer:

```yaml
initContainers:
- name: fix-nfs-perms
  image: busybox:latest
  command: ["/bin/sh", "-c"]
  args: ["mkdir -p /config/required/dirs && chmod -R 777 /config"]
  securityContext:
    runAsUser: 1000
    runAsGroup: 1000
  volumeMounts:
  - name: config
    mountPath: /config
```

## Troubleshooting

### Vault Sealed After Node Restart

Vault does not auto-unseal. After any node restart affecting the vault pod:
```bash
kubectl exec -n vault vault-0 -- vault status
# If Sealed: true, unseal with 3 keys (see Cold-Start section)
```

### Pod Stuck in Init (Vault Agent)

If Vault is sealed or unreachable, pods with `vault.hashicorp.com/agent-inject: "true"` will hang in Init:
```bash
kubectl describe pod -n <namespace> <pod-name>
# Look for: "vault-agent-init" container status
```
Fix: Unseal Vault, then the init container will complete.

### Certificate Not Issuing

```bash
# Check certificate status
kubectl get certificates -A
kubectl describe certificate -n <namespace> <cert-name>

# Check cert-manager logs
kubectl logs -n cert-manager deploy/cert-manager --tail=20

# Check if ClusterIssuer is ready
kubectl get clusterissuer letsencrypt-prod
```

### ArgoCD App OutOfSync

```bash
# Force refresh
kubectl patch app <app-name> -n argocd --type merge \
  -p '{"metadata":{"annotations":{"argocd.argoproj.io/refresh":"hard"}}}'

# Check diff
kubectl get app <app-name> -n argocd -o jsonpath='{.status.sync.status}'
```

### NFS PVC Stuck Terminating

If a PVC won't delete (stuck on finalizer):
```bash
kubectl patch pvc <pvc-name> -n <namespace> --type merge \
  -p '{"metadata":{"finalizers":null}}'
```

## Network Reference

### Internal Service Endpoints

| Service | Cluster DNS | Port |
|---|---|---|
| Vault | vault.vault.svc.cluster.local | 8200 |
| Loki | loki.loki.svc.cluster.local | 3100 |
| Prometheus | prometheus.prometheus.svc.cluster.local | 80 |
| AlertManager | alertmanager.alertmanager.svc.cluster.local | 9093 |
| Grafana | grafana.grafana.svc.cluster.local | 80 |
| PostgreSQL | postgresql.databases.svc.cluster.local | 5432 |
| Joplin | joplin-server.joplin.svc.cluster.local | 22300 |
| Harbor Core | harbor-core.harbor.svc.cluster.local | 80 |
| Browser Service | browser-service.browser-service.svc.cluster.local | 3000 |

### External URLs

| URL | Service | Access Method |
|---|---|---|
| argocd.racktocloud.com | ArgoCD | Ingress (local) |
| code.racktocloud.com | Code Server | Ingress (local) |
| grafana.racktocloud.com | Grafana | Ingress (local) |
| harbor.racktocloud.com | Harbor | Ingress + Tunnel |
| heimdall.racktocloud.com | Heimdall | Ingress (local) |
| joplin.racktocloud.com | Joplin | Ingress + Tunnel |
| k8vault.racktocloud.com | Vaultwarden | Ingress + Tunnel |
| prometheus.racktocloud.com | Prometheus | Ingress (local) |
| ai.racktocloud.com | Ollama API | Tunnel + CF Access |
