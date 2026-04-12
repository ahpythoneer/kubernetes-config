# 2026-04-11 Plaintext Credentials in Public Git Repository

**Date:** 2026-04-11
**Duration:** ~3 hours (discovery through remediation)
**Affected services:** code-server, grafana, harbor, joplin, vaultwarden, shared postgresql
**Tier impacted:** tier1 (joplin, harbor), tier2 (vaultwarden, grafana, code-server)
**Root cause:** Five plaintext credentials were committed to manifests in the public GitHub repository `ahpythoneer/kubernetes-config`, three of which shared the same reused password.

## Timeline

- **18:00 UTC** — Discovery pass against the live cluster begins. Layer 1 inventory reveals unexpected components (Rancher, GPU Operator, Twingate) not documented in the architecture.
- **20:30 UTC** — While investigating what each service consumes from Vault vs k8s Secrets, grep reveals `stringData` blocks in 5 manifest files containing plaintext passwords.
- **20:35 UTC** — Severity assessment: the repository is public. Three of five passwords are the same reused value (`H0m3L@b!25!!`). Git history contains the credentials in every commit since they were first added (~40 days ago). Credentials must be treated as permanently compromised.
- **20:45 UTC** — Phase 0 emergency response initiated. New passwords generated, Vault entries written.
- **21:00 UTC** — Rotation begins: vaultwarden (via Vault agent restart), code-server (same), grafana (via `grafana-cli admin reset-admin-password`), joplin/postgres (`ALTER USER` + k8s Secret update + restart).
- **21:15 UTC** — Harbor rotation blocked: stored password hash in harbor-db doesn't match any known candidate. Harbor had been changed out-of-band at some point. Harbor restored to pre-attempt state.
- **21:30 UTC** — Plaintext `stringData` blocks removed from all 5 manifests. Additional find: Harbor deployment had ANOTHER plaintext (`HARBOR_DATABASE_PASSWORD: C0nn3ct@2025`) hardcoded as an env var — also removed.
- **21:35 UTC** — `.gitleaks.toml` + `.github/workflows/secret-scan.yml` added to CI. Gitleaks now blocks merges that introduce secrets.
- **21:37 UTC** — Security commit `ad0d368` pushed to public `main` branch. Plaintext removed from HEAD.
- **21:45 UTC** — Post-rotation verification: all 4 rotated services healthy (2/2 Running). Harbor left in pre-attempt state.
- **21:55 UTC** — Harbor namespace deleted for fresh start (was previously a failed Helm install with a non-functional kustomize stub). Namespace placeholder committed.
- **17:12 UTC (next day)** — Postgres superuser password rotated from literal `postgres` to a random 28-char value; stored in Vault at `secret/databases/postgresql`.

## Root Cause Analysis

The root cause was **missing CI enforcement** (gitleaks was not in the pipeline) combined with **operator habits from the Docker/Portainer era** where secrets in compose files are normal. The Kubernetes manifests were written in the same style — plaintext `stringData` blocks committed directly — because:

1. No CI check existed to block the commit
2. The repo started private and was made public later without a secrets audit
3. Vault integration was partially wired (annotations existed on some deployments) but never completed for actual credential sourcing
4. The operator's password reuse pattern (`H0m3L@b!25!!` across 3 services) amplified the blast radius

This is exactly the kind of incident the PRD's NFR-S1 ("zero secrets in the configuration repository, enforced by CI") was designed to prevent — but the enforcement mechanism (gitleaks) hadn't been deployed yet because the MVP critical path hadn't reached that step.

## Resolution

**Rotated:**
- code-server password → new random value in Vault at `secret/code-server`
- Grafana admin password → new random value, hash updated via `grafana-cli`, Vault at `secret/grafana/admin`
- Joplin postgres role password → `ALTER USER` in shared postgres, runtime k8s Secret recreated, Vault at `secret/joplin/database`
- Vaultwarden admin token → new random value in Vault at `secret/vaultwarden/config`
- Postgres superuser → new random value, Vault at `secret/databases/postgresql`

**Not rotated (blocked):**
- Harbor admin password — current DB hash doesn't match any known candidate. Harbor namespace deleted for fresh reinstall.

**Preventive:**
- Gitleaks CI workflow added (`.github/workflows/secret-scan.yml`)
- Gitleaks config with project-specific allowlists (`.gitleaks.toml`)
- All plaintext `stringData` blocks removed from manifests on HEAD

**Known limitation:**
- Git history still contains the compromised credentials. Decision: accept history as tainted, rely on rotation + gitleaks. BFG rewrite deferred as unnecessary given rotation.

## Troubleshooting entries

- [docs/troubleshooting/plaintext-secrets-in-git.md](../troubleshooting/plaintext-secrets-in-git.md) — to be created; covers: how to detect, how to rotate, how to prevent recurrence

## Lessons learned

1. **Never make a private repo public without running a secrets audit first.** `gitleaks detect --source=. --log-opts="--all"` takes 10 seconds and would have caught this.
2. **"I'll set up Vault later" is a security debt that compounds.** The Vault agent annotations were on the deployments but never completed. Partial integration is worse than no integration — it creates false confidence.
3. **Password reuse across services is a blast-radius multiplier.** Three services sharing `H0m3L@b!25!!` meant compromising one = compromising three.
4. **Discovery passes before architectural work are mandatory, not optional.** If we had continued directly to Story 1.1 (add 3rd control-plane node), these plaintext credentials would have stayed in git while we argued about etcd quorum.
5. **The "paid-off home before renovations" philosophy applies to security too.** You can't build a reference architecture on top of exposed credentials.
