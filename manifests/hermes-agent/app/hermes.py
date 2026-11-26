"""Hermes: chat-ops front door for the racktocloud homelab (homelab/ops#19).

Telegram (long polling, only the allowed user) -> local LLM with tools -> Forgejo issues,
read-only cluster status, and Claude Code jobs via claude-runner.

Rules (user decisions, 2026-11-14):
  - chatting, reading, status and creating/updating issues need no approval
  - anything that changes the cluster or git: Claude writes a plan first, Hermes posts it with
    Approve/Reject buttons, and only the user's Approve starts the execute job
  - every piece of work is tied to a Forgejo issue in homelab/ops

Standard library only. Secrets come from files rendered by the Vault agent in /vault/secrets.
"""
import json
import logging
import os
import re
import secrets
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

log = logging.getLogger("hermes")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

SECRETS = "/vault/secrets"
STATE_FILE = os.environ.get("STATE_FILE", "/app/state/state.json")
PRIMARY = (os.environ["PRIMARY_LLM_URL"], os.environ["PRIMARY_MODEL"])
FALLBACK = (os.environ["FALLBACK_LLM_URL"], os.environ["FALLBACK_MODEL"])
# intent routing: the small model is fast (<1 s) and scored 15/15 in tests; big model as fallback
ROUTERS = (FALLBACK, PRIMARY)
RUNNER = os.environ.get("RUNNER_URL", "http://claude-runner.code-server.svc:8787")
FORGEJO = os.environ.get("FORGEJO_URL", "https://git.racktocloud.com")
REPO = os.environ.get("FORGEJO_REPO", "homelab/ops")
PROM = os.environ.get("PROMETHEUS_URL", "http://prometheus.prometheus.svc")
SOUL = open("/app/SOUL.md").read()
PLAN_TTL = 24 * 3600
HISTORY = 16


def secret(name):
    with open(os.path.join(SECRETS, name)) as f:
        return f.read().strip()


TG_TOKEN = secret("telegram-token")
ALLOWED = int(secret("allowed-user"))
RUNNER_TOKEN = secret("runner-token")
FJ_TOKEN = secret("forgejo-token")

# ---------------------------------------------------------------- http helpers
def http(method, url, body=None, headers=None, timeout=60, ctx=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json", **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        raw = r.read()
        return json.loads(raw) if raw else {}


def tg(method, **params):
    return http("POST", f"https://api.telegram.org/bot{TG_TOKEN}/{method}", params, timeout=70)


def fj(method, path, body=None):
    return http(method, f"{FORGEJO}/api/v1/repos/{REPO}{path}", body, {"Authorization": f"token {FJ_TOKEN}"})


def runner(method, path, body=None):
    return http(method, f"{RUNNER}{path}", body, {"Authorization": f"Bearer {RUNNER_TOKEN}"})


K8S_TOKEN = "/var/run/secrets/kubernetes.io/serviceaccount/token"
K8S_CTX = ssl.create_default_context(cafile="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")


def k8s(path):
    tok = open(K8S_TOKEN).read().strip()
    return http("GET", f"https://kubernetes.default.svc{path}", headers={"Authorization": f"Bearer {tok}"}, ctx=K8S_CTX)


# ---------------------------------------------------------------- state (survives restarts)
_lock = threading.Lock()


def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"offset": 0, "plans": {}, "jobs": {}}


STATE = load_state()


def save_state():
    """Persist STATE. Several threads mutate it, so serialising can hit "dictionary changed
    size during iteration"; that used to kill job watchers silently (homelab/ops#19: a result
    arrived 4 days late). Retry, and never raise into the caller."""
    with _lock:
        for _ in range(5):
            try:
                data = json.dumps(STATE)
                break
            except RuntimeError:
                time.sleep(0.05)
        else:
            log.error("save_state: could not serialise state")
            return
        try:
            os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
            tmp = f"{STATE_FILE}.{threading.get_ident()}.tmp"
            with open(tmp, "w") as f:
                f.write(data)
            os.replace(tmp, STATE_FILE)
        except OSError as e:
            log.error("save_state failed: %s", e)


# ---------------------------------------------------------------- conversation log (accuracy reviews)
CHAT_LOG = os.environ.get("CHAT_LOG", os.path.join(os.path.dirname(STATE_FILE), "chat-log.jsonl"))


def log_turn(**rec):
    try:
        if os.path.exists(CHAT_LOG) and os.path.getsize(CHAT_LOG) > 5_000_000:
            os.replace(CHAT_LOG, CHAT_LOG + ".1")
        with open(CHAT_LOG, "a") as f:
            f.write(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), **rec})[:8000] + "\n")
    except OSError as e:
        log.warning("chat log: %s", e)


# ---------------------------------------------------------------- telegram output
def plain(text):
    """Telegram plain text: drop markdown bold/headers that would show as raw symbols."""
    text = re.sub(r"\*\*(.+?)\*\*", r"\1", text)
    return re.sub(r"^#{1,6}\s*", "", text, flags=re.M)


def say(text, buttons=None):
    text = plain(text) or "(empty)"
    chunks = [text[i:i + 3900] for i in range(0, len(text), 3900)]
    msg = None
    for i, chunk in enumerate(chunks):
        params = {"chat_id": ALLOWED, "text": chunk, "disable_web_page_preview": True}
        if buttons and i == len(chunks) - 1:
            params["reply_markup"] = {"inline_keyboard": [buttons]}
        msg = tg("sendMessage", **params)
    return msg


def edit(message_id, text):
    try:
        tg("editMessageText", chat_id=ALLOWED, message_id=message_id, text=plain(text)[:3900], disable_web_page_preview=True)
    except urllib.error.HTTPError:
        pass  # "message is not modified" and the like


# ---------------------------------------------------------------- tools for the LLM
def label_ids(names):
    labels = {l["name"]: l["id"] for l in fj("GET", "/labels?limit=100")}
    return [labels[n] for n in names or [] if n in labels]


def t_list_issues(state="open", label=None):
    q = f"/issues?type=issues&state={state}&limit=50" + (f"&labels={urllib.parse.quote(label)}" if label else "")
    items = [{"number": i["number"], "title": i["title"].split("\n")[0][:120], "labels": [l["name"] for l in i["labels"]], "state": i["state"]}
             for i in fj("GET", q)]
    # the count is given explicitly: the model miscounted a 24-item list as 29 (2026-11-26 eval)
    return {"count": len(items), "state": state, "label": label, "issues": items}


def t_get_issue(number):
    i = fj("GET", f"/issues/{int(number)}")
    comments = fj("GET", f"/issues/{int(number)}/comments")[-8:]
    return {"number": i["number"], "title": i["title"], "state": i["state"], "labels": [l["name"] for l in i["labels"]],
            "body": i["body"][:4000], "comments": [{"by": c["user"]["login"], "at": c["created_at"], "body": c["body"][:1500]} for c in comments]}


def t_create_issue(title, body="", labels=None):
    i = fj("POST", "/issues", {"title": title, "body": body + "\n\n_Filed by Hermes from Telegram._", "labels": label_ids(labels)})
    return {"number": i["number"], "url": i["html_url"]}


def t_comment_issue(number, body):
    fj("POST", f"/issues/{int(number)}/comments", {"body": body})
    return {"ok": True, "number": int(number)}


def t_close_issue(number, comment=None):
    if comment:
        t_comment_issue(number, comment)
    fj("PATCH", f"/issues/{int(number)}", {"state": "closed"})
    return {"ok": True, "closed": int(number)}


def t_cluster_status():
    out = {}
    nodes = k8s("/api/v1/nodes")["items"]
    out["nodes"] = [{"name": n["metadata"]["name"], "ready": any(c["type"] == "Ready" and c["status"] == "True" for c in n["status"]["conditions"]),
                     "cordoned": bool(n["spec"].get("unschedulable"))} for n in nodes]
    bad, leftovers = [], []
    for p in k8s("/api/v1/pods")["items"]:
        phase = p["status"].get("phase")
        if phase == "Succeeded":
            continue
        if phase in ("Failed", "Unknown"):
            # dead pod objects (e.g. from a node reboot) whose workload was already replaced:
            # clutter, not an outage. They used to be reported as failures.
            leftovers.append(f'{p["metadata"]["namespace"]}/{p["metadata"]["name"]} {phase} since {p["metadata"]["creationTimestamp"][:10]}')
            continue
        cs = p["status"].get("containerStatuses") or []
        if phase != "Running" or not all(c.get("ready") for c in cs):
            reasons = [c["state"].get("waiting", {}).get("reason") for c in cs if c["state"].get("waiting")]
            bad.append(f'{p["metadata"]["namespace"]}/{p["metadata"]["name"]} {phase} {",".join(r for r in reasons if r)}'.strip())
    out["unhealthy_pods"] = bad[:30]
    out["leftover_dead_pods"] = leftovers[:20]  # not running, safe to delete; NOT an outage
    apps = k8s("/apis/argoproj.io/v1alpha1/namespaces/argocd/applications")["items"]
    out["argocd_not_synced_or_healthy"] = [f'{a["metadata"]["name"]}: {a["status"].get("sync", {}).get("status")}/{a["status"].get("health", {}).get("status")}'
                                           for a in apps if (a["status"].get("sync", {}).get("status"), a["status"].get("health", {}).get("status")) != ("Synced", "Healthy")]
    out["argocd_apps"] = len(apps)
    try:
        alerts = http("GET", f"{PROM}/api/v1/alerts", timeout=10)["data"]["alerts"]
        out["firing_alerts"] = [f'{a["labels"]["alertname"]} {a["labels"].get("namespace", "")} {a["labels"].get("pod", a["labels"].get("instance", ""))}'.strip()
                                for a in alerts if a["state"] == "firing"]
    except Exception as e:  # noqa: BLE001
        out["firing_alerts"] = f"prometheus unreachable: {e}"
    return out


def _age(ts):
    secs = time.time() - time.mktime(time.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S")) + time.timezone
    return f"{int(secs // 86400)}d" if secs >= 86400 else f"{int(secs // 3600)}h" if secs >= 3600 else f"{int(secs // 60)}m"


def t_find_pods(name):
    """Pods whose name or namespace contains `name`: where they run and how they are doing."""
    out = []
    for p in k8s("/api/v1/pods")["items"]:
        ns, pn = p["metadata"]["namespace"], p["metadata"]["name"]
        if name.lower() not in pn.lower() and name.lower() != ns.lower():
            continue
        cs = p["status"].get("containerStatuses") or []
        out.append({"namespace": ns, "pod": pn, "node": p["spec"].get("nodeName"), "phase": p["status"].get("phase"),
                    "ready": f"{sum(1 for c in cs if c.get('ready'))}/{len(cs)}", "restarts": sum(c.get("restartCount", 0) for c in cs),
                    "age": _age(p["metadata"]["creationTimestamp"])})
    return out[:30] or {"result": f"no pod matches '{name}'"}


def t_cluster_info():
    """Kubernetes version and per-node versions, OS, kernel and capacity."""
    v = k8s("/version")
    nodes = []
    for n in k8s("/api/v1/nodes")["items"]:
        i = n["status"]["nodeInfo"]
        roles = [k.split("/")[1] for k in n["metadata"].get("labels", {}) if k.startswith("node-role.kubernetes.io/")]
        nodes.append({"name": n["metadata"]["name"], "roles": roles or ["worker"], "kubelet": i["kubeletVersion"], "os": i["osImage"],
                      "kernel": i["kernelVersion"], "containerd": i["containerRuntimeVersion"],
                      "cpu": n["status"]["capacity"].get("cpu"), "memory": n["status"]["capacity"].get("memory"),
                      "gpus": n["status"]["capacity"].get("nvidia.com/gpu", "0")})
    return {"kubernetes": v.get("gitVersion"), "nodes": nodes}


# curated, known-good PromQL so the model never has to write queries
METRICS = {
    "gpu_temperature_c": "max by (Hostname) (DCGM_FI_DEV_GPU_TEMP)",
    "gpu_utilization_pct": "max by (Hostname) (DCGM_FI_DEV_GPU_UTIL)",
    "node_cpu_busy_pct": '100 - avg by (instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100',
    "node_memory_used_pct": "(1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes) * 100",
    "node_root_disk_used_pct": '(1 - node_filesystem_avail_bytes{mountpoint="/"} / node_filesystem_size_bytes{mountpoint="/"}) * 100',
    "clipdrop_coupons_live": "clipdrop_coupons_live",
    "clipdrop_last_crawl_age_hours": "(time() - clipdrop_last_crawl_timestamp_seconds) / 3600",
    "vaultwarden_backup_age_hours": "(time() - vaultwarden_backup_last_success_timestamp_seconds) / 3600",
    "postgres_backup_age_hours": '(time() - kube_cronjob_status_last_successful_time{cronjob="postgresql-backup"}) / 3600',
}


def t_homelab_metrics(names=None):
    """Live numbers from Prometheus. names: subset of METRICS keys (default: all)."""
    out = {}
    for key in names or list(METRICS):
        if key not in METRICS:
            out[key] = "unknown metric"
            continue
        try:
            q = urllib.parse.quote(METRICS[key])
            res = http("GET", f"{PROM}/api/v1/query?query={q}", timeout=10)["data"]["result"]
            out[key] = {(",".join(f"{k}={v}" for k, v in r["metric"].items() if k in ("instance", "Hostname", "scope")) or "value"):
                        round(float(r["value"][1]), 1) for r in res} or "no data"
        except Exception as e:  # noqa: BLE001
            out[key] = f"error: {e}"
    return out


def t_ask_claude(task, issue=None, wants_change=False, title=None):
    """Hand work to Claude Code. Always a read-only PLAN job first."""
    if not issue:
        short = (title or task.split("\n")[0])[:80].strip()
        created = t_create_issue(short, f"Requested via Telegram:\n\n{task}", ["type/chore" if wants_change else "type/idea"])
        issue = created["number"]
    job = runner("POST", "/v1/jobs", {"mode": "plan", "task": task, "issue": int(issue)})
    STATE["jobs"][job["id"]] = {"kind": "plan", "issue": int(issue), "task": task, "wants_change": bool(wants_change), "since": 0, "created": time.time()}
    save_state()
    start_watcher(job["id"])
    return {"submitted": True, "job": job["id"], "issue": int(issue),
            "note": "Claude is investigating read-only. The plan/answer will be posted to the chat"
                    + (" with Approve/Reject buttons." if wants_change else ".")}


TOOLS = {
    "list_issues": (t_list_issues, "List issues in the homelab/ops tracker, with their count. For ONE issue use get_issue instead.",
                    {"state": {"type": "string", "enum": ["open", "closed", "all"]}, "label": {"type": "string", "description": "optional label such as area/backup, priority/high, type/bug"}}, []),
    "get_issue": (t_get_issue, "Read one issue: its state (open/closed), labels, body and latest comments. Use for 'is #N open?', 'latest on #N'.", {"number": {"type": "integer"}}, ["number"]),
    "create_issue": (t_create_issue, "File a new issue (bug, idea or chore). Labels: area/{cluster,network,security,backup,apps,hardware}, priority/{high,medium,low}, type/{bug,chore,idea}.",
                     {"title": {"type": "string"}, "body": {"type": "string"}, "labels": {"type": "array", "items": {"type": "string"}}}, ["title"]),
    "comment_issue": (t_comment_issue, "Add a comment to an issue.", {"number": {"type": "integer"}, "body": {"type": "string"}}, ["number", "body"]),
    "close_issue": (t_close_issue, "Close an issue, optionally with a closing comment.", {"number": {"type": "integer"}, "comment": {"type": "string"}}, ["number"]),
    "cluster_status": (t_cluster_status, "Live cluster health: nodes, unhealthy pods, leftover dead pods (clutter, not outages), ArgoCD apps not Synced/Healthy, firing alerts.", {}, []),
    "find_pods": (t_find_pods, "Find pods by (part of) their name or by namespace: which node they run on, phase, readiness, restarts, age. Use for 'where does X run?', 'is X up?', 'how often did X restart?'.",
                  {"name": {"type": "string", "description": "pod name fragment or namespace, e.g. ollama, grafana, clipdrop"}}, ["name"]),
    "cluster_info": (t_cluster_info, "Kubernetes version and per-node details: roles, kubelet version, OS, kernel, containerd, CPU, memory, GPUs.", {}, []),
    "homelab_metrics": (t_homelab_metrics, "Live numbers from Prometheus: " + ", ".join(METRICS) + ". Use for GPU temperature/usage, node CPU/memory/disk, ClipDrop coupon counts and crawl age, backup ages.",
                        {"names": {"type": "array", "items": {"type": "string", "enum": list(METRICS)}, "description": "which metrics (omit for all)"}}, []),
    "ask_claude": (t_ask_claude, "Hand a task to Claude Code, which can read the cluster and the GitOps repo. Use for investigations ('why is X failing?') and for ANY change "
                   "(deploy, fix, upgrade, config edit, restart). Set wants_change=true when the user wants something changed: Claude then returns a plan that the user must approve.",
                   {"task": {"type": "string", "description": "complete, self-contained description of what the user wants"},
                    "issue": {"type": "integer", "description": "related homelab/ops issue number, if any"},
                    "wants_change": {"type": "boolean"}}, ["task"]),
}
# ask_claude is NOT offered to the chat model: work is dispatched by route() in code, so the
# model can never "say" it started a job without one existing (it did exactly that on 2026-11-14).
TOOL_SPECS = [{"type": "function", "function": {"name": n, "description": d, "parameters": {"type": "object", "properties": p, "required": r}}}
              for n, (_, d, p, r) in TOOLS.items() if n != "ask_claude"]


# ---------------------------------------------------------------- LLM
def llm(messages):
    for url, model in (PRIMARY, FALLBACK):
        try:
            r = http("POST", f"{url}/api/chat", {"model": model, "messages": messages, "tools": TOOL_SPECS, "stream": False,
                                                 "options": {"temperature": 0.3, "num_ctx": 16384}, "keep_alive": "30m"}, timeout=300)
            return r["message"]
        except Exception as e:  # noqa: BLE001
            log.warning("LLM %s/%s failed: %s", url, model, e)
    raise RuntimeError("no LLM reachable (DGX Spark and cluster Ollama both failed)")


HIST = []


# "Let me check that for you." with no tool call is an empty promise (seen in the 2026-11-26 eval)
PROMISE = re.compile(r"^\W*(let me|i('ll| will)|one moment|checking)\b.{0,60}\b(check|look|see|find|get|pull)\b", re.I)
LAST_TOOLS = []


def chat(text):
    HIST.append({"role": "user", "content": text})
    del HIST[:-HISTORY]
    # the model doesn't know the date; without it, "Nov 14" became "yesterday" in the eval
    now = time.strftime("%A %Y-%m-%d %H:%M %Z")
    messages = [{"role": "system", "content": f"{SOUL}\n\nCurrent date and time: {now}."}] + HIST
    LAST_TOOLS.clear()
    nudged = False
    for _ in range(7):
        msg = llm(messages)
        calls = msg.get("tool_calls") or []
        messages.append({"role": "assistant", "content": msg.get("content", ""), "tool_calls": calls})
        if not calls:
            reply = (msg.get("content") or "").strip()
            if (not reply or PROMISE.search(reply)) and not nudged:
                nudged = True
                messages.append({"role": "user", "content": "(system) You did not call a tool. Call the right tool now, "
                                 "or answer in one sentence that none of your tools can tell, and suggest asking 'look into ...' for Claude."})
                continue
            reply = reply or "(no answer)"
            HIST.append({"role": "assistant", "content": reply})
            return reply
        for c in calls:
            name, args = c["function"]["name"], c["function"].get("arguments") or {}
            if isinstance(args, str):
                args = json.loads(args or "{}")
            log.info("tool %s %s", name, json.dumps(args)[:200])
            LAST_TOOLS.append(name)
            try:
                if name in TOOLS:
                    allowed = TOOLS[name][2]
                    dropped = [k for k in args if k not in allowed]
                    args = {k: v for k, v in args.items() if k in allowed}
                    result = TOOLS[name][0](**args)
                    if dropped:
                        result = {"note": f"ignored unknown arguments {dropped}", "result": result}
                else:
                    result = {"error": f"unknown tool {name}"}
            except Exception as e:  # noqa: BLE001
                result = {"error": str(e)}
            messages.append({"role": "tool", "content": json.dumps(result)[:12000]})
    return "I went in circles with my tools; please rephrase or be more specific."


# ---------------------------------------------------------------- routing (decided by code, not by the chat model)
ROUTE_SCHEMA = {"type": "object", "required": ["intent", "task", "issue", "title"], "properties": {
    "intent": {"type": "string", "enum": ["change", "investigate", "job_status", "issues", "chat"]},
    "task": {"type": "string"}, "issue": {"type": ["integer", "null"]}, "title": {"type": "string"}}}
ROUTE_PROMPT = """Classify the user's latest message for a homelab chat-ops bot. Reply with JSON only.
intent:
- "issues": ANY question or request about the issue tracker or a specific issue: how many issues,
  what's open, list/show/search issues, "is #26 still open?", "what's the latest on issue 20?",
  "status of #19", file/create a bug, idea or chore, comment on, label, close or reopen an issue.
- "change": the user wants something DONE to the cluster, git repo, a service or a config:
  restart, deploy, fix, upgrade, roll back, scale, edit, delete or create a resource, apply,
  rotate. (Filing or closing an issue is "issues", not "change".)
- "investigate": the user wants an explanation that needs digging into the cluster or repo:
  why is X failing / restarting / slow, what changed, look into X, debug X, check X in detail.
- "job_status": ONLY about Claude jobs or plans started from this chat ("is it done?", "did the
  restart work?", "checking up on that", "status of my jobs"). A question naming an issue number
  is "issues", not "job_status".
- "chat": everything else: greetings, quick facts and health ("how's the cluster?", "any
  alerts?", "which node runs ollama?", "what k8s version?", "how hot is the GPU?", "how many
  coupons on clipdrop?"), general questions.
task: for change/investigate, a complete self-contained instruction for an engineer, resolving
references from the conversation (e.g. "do that" -> what "that" is). Otherwise "".
title: for change/investigate, a short issue title (max 70 chars, no quotes). Otherwise "".
issue: the homelab/ops issue number if the user mentions or clearly refers to one, else null.

Examples:
"how many open issues do we have?" -> issues
"is issue 26 still open?" -> issues (issue 26)
"what's the latest on #20?" -> issues (issue 20)
"did it work?" (after asking for a restart) -> job_status
"restart grafana" -> change, title "Restart grafana"
"why does harbor keep restarting?" -> investigate, title "Investigate Harbor restarts"
"which node is ollama on?" -> chat"""


def route(text):
    context = [{"role": m["role"], "content": m["content"][:600]} for m in HIST[-6:] if m["role"] in ("user", "assistant")]
    for url, model in ROUTERS:
        try:
            r = http("POST", f"{url}/api/chat", {"model": model, "stream": False, "format": ROUTE_SCHEMA, "keep_alive": "30m",
                                                 "options": {"temperature": 0},
                                                 "messages": [{"role": "system", "content": ROUTE_PROMPT}] + context + [{"role": "user", "content": text}]}, timeout=120)
            out = json.loads(r["message"]["content"])
            log.info("route %s/%s: %s issue=%s", model, out.get("intent"), text[:80], out.get("issue"))
            return out
        except Exception as e:  # noqa: BLE001
            log.warning("router %s failed: %s", model, e)
    return {"intent": "chat", "task": "", "issue": None, "title": ""}


def job_status_text():
    lines = []
    for pid, p in STATE["plans"].items():
        lines.append(f"⏳ Plan for #{p['issue']} is waiting for your Approve/Reject (scroll up to the 📋 message).")
    try:
        jobs = runner("GET", "/v1/jobs")
    except Exception as e:  # noqa: BLE001
        return f"I can't reach the Claude runner right now ({e})."
    for j in jobs[-6:]:
        icon = {"queued": "🕐", "running": "🔧", "done": "✅", "failed": "❌", "timeout": "⌛", "cancelled": "🚫"}.get(j["status"], "•")
        lines.append(f"{icon} {j['mode']} job {j['id']} on #{j['issue']}: {j['status']}")
    return "\n".join(lines) or "No Claude jobs or pending plans right now. Nothing has been started."


# replies that claim actions/results are only allowed to come from job results, never from chat
CLAIM = re.compile(r"(asked|handed|passed|sent).{0,20}claude|claude( code)? (is|has|reports|reported|will|says|said|finished|completed)|"
                   r"successfully (restarted|deployed|applied|rolled|scaled|upgraded|updated|deleted)|"
                   r"\b(i('ve| have)|has been|was) (restarted|deployed|applied|rolled back|scaled|upgraded)", re.I)


def guarded(reply):
    # Reading the record (e.g. get_issue on #20) may truthfully say "Claude restarted it"; the
    # guard is for invented actions, i.e. claims made without any tool behind them.
    if CLAIM.search(reply) and not LAST_TOOLS:
        log.warning("blocked an unfounded action claim: %s", reply[:200])
        return ("I can't do or check work from plain chat, and I haven't started anything. "
                "Tell me directly what you want done (e.g. \"restart clipdrop\") and I'll hand it to Claude for a plan, "
                "or ask \"status of my jobs\".")
    return reply


# ---------------------------------------------------------------- Claude jobs
WATCHERS = {}


def start_watcher(job_id):
    t = WATCHERS.get(job_id)
    if t and t.is_alive():
        return
    WATCHERS[job_id] = threading.Thread(target=watch_job, args=(job_id,), daemon=True)
    WATCHERS[job_id].start()


def watchdog():
    """Called from the main loop (at least every ~50 s): any tracked job without a live watcher gets one."""
    for job_id in list(STATE["jobs"]):
        t = WATCHERS.get(job_id)
        if not (t and t.is_alive()):
            log.warning("watchdog: restarting watcher for job %s", job_id)
            start_watcher(job_id)


def watch_job(job_id):
    try:
        _watch_job(job_id)
    except Exception:  # noqa: BLE001
        # never die silently: the watchdog restarts us, and the job state is still on disk
        log.exception("watcher for job %s crashed", job_id)


def _watch_job(job_id):
    meta = STATE["jobs"].get(job_id)
    if not meta:
        return
    status_msg = None
    last_edit = 0
    while True:
        time.sleep(8)
        try:
            j = runner("GET", f"/v1/jobs/{job_id}?since={meta['since']}")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                say(f"⚠️ Claude job {job_id} (#{meta['issue']}) was lost (runner restarted before it finished). Ask again to retry.")
                STATE["jobs"].pop(job_id, None)
                save_state()
                return
            continue
        except Exception:  # noqa: BLE001
            continue
        if j["events"]:
            meta["since"] = j["events"][-1]["n"] + 1
            steps = [f'• {e["tool"]}: {e["detail"][:80]}' for e in j["events"] if e["type"] == "tool"][-6:]
            if steps and time.time() - last_edit > 20:
                head = f"🔧 Claude {meta['kind']} job on #{meta['issue']}: working…"
                if status_msg:
                    edit(status_msg, head + "\n" + "\n".join(steps))
                else:
                    status_msg = say(head + "\n" + "\n".join(steps))["result"]["message_id"]
                last_edit = time.time()
        if j["status"] in ("done", "failed", "timeout", "cancelled"):
            return job_finished(job_id, meta, j)


def job_finished(job_id, meta, j):
    result = j.get("result") or "(no output)"
    issue = meta["issue"]
    STATE["jobs"].pop(job_id, None)
    if j["status"] != "done":
        say(f"❌ Claude {meta['kind']} job on #{issue} ended: {j['status']}\n\n{result[:3000]}")
        t_comment_issue(issue, f"Claude {meta['kind']} job `{job_id}` ended **{j['status']}**.\n\n{result}")
        save_state()
        return
    if meta["kind"] == "plan" and meta["wants_change"] and re.match(r"\W*BLOCKED:", result):
        # Claude says it can't carry this out with its access: don't offer Approve (rules.md #9)
        t_comment_issue(issue, f"**Blocked**: Claude can't carry this out with its current access (job `{job_id}`):\n\n{result}")
        say(f"🚧 #{issue} can't be done by Claude as things stand. Nothing to approve.\n\n{result}")
    elif meta["kind"] == "plan" and meta["wants_change"]:
        pid = secrets.token_hex(4)
        STATE["plans"][pid] = {"issue": issue, "task": meta["task"], "plan": result, "created": time.time()}
        t_comment_issue(issue, f"**Plan proposed by Claude** (job `{job_id}`), waiting for approval in Telegram:\n\n{result}")
        say(f"📋 Plan for #{issue}\n\n{result}",
            buttons=[{"text": "✅ Approve", "callback_data": f"approve:{pid}"}, {"text": "❌ Reject", "callback_data": f"reject:{pid}"}])
    elif meta["kind"] == "plan":
        t_comment_issue(issue, f"**Answer from Claude** (read-only job `{job_id}`):\n\n{result}")
        say(f"🔎 #{issue}\n\n{result}")
    else:
        t_comment_issue(issue, f"**Executed by Claude** (job `{job_id}`, approved in Telegram):\n\n{result}")
        say(f"✅ Done: #{issue}\n\n{result}",
            buttons=[{"text": f"✅ Close #{issue}", "callback_data": f"close:{issue}"}, {"text": "Keep open", "callback_data": f"keep:{issue}"}])
    save_state()


def on_button(q):
    tg("answerCallbackQuery", callback_query_id=q["id"])
    if q["from"]["id"] != ALLOWED:
        return
    action, _, pid = q.get("data", "").partition(":")
    if action in ("close", "keep"):
        tg("editMessageReplyMarkup", chat_id=ALLOWED, message_id=q["message"]["message_id"], reply_markup={"inline_keyboard": []})
        if action == "close":
            t_close_issue(int(pid), "Closed from Telegram after Claude's successful execution.")
            return say(f"Closed #{pid}.")
        return say(f"OK, #{pid} stays open.")
    plan = STATE["plans"].pop(pid, None)
    save_state()
    msg_id = q["message"]["message_id"]
    if not plan:
        return say("That plan was already handled or has expired.")
    if time.time() - plan["created"] > PLAN_TTL:
        return say(f"The plan for #{plan['issue']} is older than 24 h; ask again for a fresh one.")
    tg("editMessageReplyMarkup", chat_id=ALLOWED, message_id=msg_id, reply_markup={"inline_keyboard": []})
    if action == "reject":
        t_comment_issue(plan["issue"], "Plan **rejected** by the user in Telegram.")
        return say(f"Rejected. Nothing was changed (#{plan['issue']}).")
    job = runner("POST", "/v1/jobs", {"mode": "execute", "task": plan["task"], "plan": plan["plan"], "issue": plan["issue"]})
    STATE["jobs"][job["id"]] = {"kind": "execute", "issue": plan["issue"], "task": plan["task"], "wants_change": True, "since": 0, "created": time.time()}
    save_state()
    t_comment_issue(plan["issue"], f"Plan **approved** by the user in Telegram; Claude execute job `{job['id']}` started.")
    say(f"▶️ Approved. Claude is executing #{plan['issue']} (job {job['id']}). I'll report back here.")
    start_watcher(job["id"])


# ---------------------------------------------------------------- commands without the LLM
def cmd(text):
    c = text.split()[0].split("@")[0].lower()
    if c in ("/start", "/help"):
        return say("Hermes here 👋 Just talk to me:\n• \"what's open?\" / \"show #6\" / \"file a bug: …\"\n• \"how's the cluster?\"\n"
                   "• \"why is X failing?\" → Claude investigates (read-only)\n• \"deploy/fix/change …\" → Claude plans, you Approve, then it executes\n\n"
                   "Shortcuts: /status /issues /jobs /reset")
    if c == "/status":
        s = t_cluster_status()
        ready = sum(n["ready"] for n in s["nodes"])
        lines = [f"Nodes ready: {ready}/{len(s['nodes'])}", f"ArgoCD apps: {s['argocd_apps']}, not OK: {s['argocd_not_synced_or_healthy'] or 'none'}",
                 f"Unhealthy pods: {s['unhealthy_pods'] or 'none'}", f"Firing alerts: {s['firing_alerts'] or 'none'}"]
        if s.get("leftover_dead_pods"):
            lines.append(f"Leftover dead pods (clutter, not outages): {len(s['leftover_dead_pods'])}")
        return say("\n".join(lines))
    if c == "/issues":
        items = t_list_issues("open")
        return say("\n".join(f"#{i['number']} {i['title']}  [{', '.join(l.split('/')[1] for l in i['labels'])}]" for i in items) or "No open issues.")
    if c == "/jobs":
        jobs = runner("GET", "/v1/jobs")
        return say("\n".join(f"{j['id']} {j['mode']} #{j['issue']} {j['status']}" for j in jobs[-10:]) or "No jobs yet.")
    if c == "/reset":
        HIST.clear()
        return say("Conversation memory cleared.")
    return None


# ---------------------------------------------------------------- main loop
def resume():
    for job_id in list(STATE["jobs"]):
        start_watcher(job_id)
    now = time.time()
    for pid in [p for p, v in STATE["plans"].items() if now - v["created"] > PLAN_TTL]:
        STATE["plans"].pop(pid)
    save_state()


def handle(update):
    if "callback_query" in update:
        return on_button(update["callback_query"])
    m = update.get("message") or {}
    sender = m.get("from", {}).get("id")
    if sender != ALLOWED:
        log.warning("ignored message from user %s", sender)
        return
    text = (m.get("text") or "").strip()
    if not text:
        return
    if text.startswith("/") and cmd(text) is not None:
        return
    tg("sendChatAction", chat_id=ALLOWED, action="typing")
    t0 = time.time()
    r = route(text)
    intent, issue = r.get("intent"), r.get("issue")
    LAST_TOOLS.clear()
    if intent in ("change", "investigate"):
        task = (r.get("task") or text) + f"\n\nThe user's exact words: {text}"
        res = t_ask_claude(task, issue, wants_change=(intent == "change"), title=r.get("title") or text)
        reply = (f"📝 On it: Claude is drafting a plan for #{res['issue']} (job {res['job']}). You'll get Approve/Reject buttons here; nothing changes before you approve."
                 if intent == "change" else
                 f"🔎 Claude is looking into it read-only (#{res['issue']}, job {res['job']}). The answer will arrive here in a few minutes.")
    elif intent == "job_status":
        reply = job_status_text()
    else:
        reply = guarded(chat(text))
        log_turn(text=text, intent=intent, issue=issue, tools=list(LAST_TOOLS), reply=reply, secs=round(time.time() - t0, 1))
        return say(reply)
    HIST.extend([{"role": "user", "content": text}, {"role": "assistant", "content": reply}])
    del HIST[:-HISTORY]
    log_turn(text=text, intent=intent, issue=issue, tools=list(LAST_TOOLS), reply=reply, secs=round(time.time() - t0, 1))
    say(reply)


def main():
    me = tg("getMe")["result"]["username"]
    log.info("Hermes chat-ops up as @%s, primary %s, fallback %s", me, PRIMARY[1], FALLBACK[1])
    resume()
    while True:
        try:
            r = tg("getUpdates", offset=STATE["offset"], timeout=50, allowed_updates=["message", "callback_query"])
        except Exception as e:  # noqa: BLE001
            log.warning("getUpdates failed: %s", e)
            time.sleep(5)
            continue
        watchdog()
        for u in r.get("result", []):
            STATE["offset"] = u["update_id"] + 1
            save_state()
            try:
                handle(u)
            except Exception as e:  # noqa: BLE001
                log.exception("update failed")
                try:
                    say(f"⚠️ Something went wrong: {e}")
                except Exception:  # noqa: BLE001
                    pass


if __name__ == "__main__":
    main()
