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
    with _lock:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        tmp = STATE_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(STATE, f)
        os.replace(tmp, STATE_FILE)


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
    return [{"number": i["number"], "title": i["title"], "labels": [l["name"] for l in i["labels"]], "state": i["state"]} for i in fj("GET", q)]


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
    bad = []
    for p in k8s("/api/v1/pods")["items"]:
        phase = p["status"].get("phase")
        if phase == "Succeeded":
            continue
        cs = p["status"].get("containerStatuses") or []
        if phase != "Running" or not all(c.get("ready") for c in cs):
            reasons = [c["state"].get("waiting", {}).get("reason") for c in cs if c["state"].get("waiting")]
            bad.append(f'{p["metadata"]["namespace"]}/{p["metadata"]["name"]} {phase} {",".join(r for r in reasons if r)}'.strip())
    out["unhealthy_pods"] = bad[:30]
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


def t_ask_claude(task, issue=None, wants_change=False):
    """Hand work to Claude Code. Always a read-only PLAN job first."""
    if not issue:
        created = t_create_issue(task[:90], f"Requested via Telegram:\n\n{task}", ["type/chore" if wants_change else "type/idea"])
        issue = created["number"]
    job = runner("POST", "/v1/jobs", {"mode": "plan", "task": task, "issue": int(issue)})
    STATE["jobs"][job["id"]] = {"kind": "plan", "issue": int(issue), "task": task, "wants_change": bool(wants_change), "since": 0, "created": time.time()}
    save_state()
    threading.Thread(target=watch_job, args=(job["id"],), daemon=True).start()
    return {"submitted": True, "job": job["id"], "issue": int(issue),
            "note": "Claude is investigating read-only. The plan/answer will be posted to the chat"
                    + (" with Approve/Reject buttons." if wants_change else ".")}


TOOLS = {
    "list_issues": (t_list_issues, "List issues in the homelab/ops tracker.",
                    {"state": {"type": "string", "enum": ["open", "closed", "all"]}, "label": {"type": "string", "description": "optional label such as area/backup, priority/high, type/bug"}}, []),
    "get_issue": (t_get_issue, "Read one issue with its latest comments.", {"number": {"type": "integer"}}, ["number"]),
    "create_issue": (t_create_issue, "File a new issue (bug, idea or chore). Labels: area/{cluster,network,security,backup,apps,hardware}, priority/{high,medium,low}, type/{bug,chore,idea}.",
                     {"title": {"type": "string"}, "body": {"type": "string"}, "labels": {"type": "array", "items": {"type": "string"}}}, ["title"]),
    "comment_issue": (t_comment_issue, "Add a comment to an issue.", {"number": {"type": "integer"}, "body": {"type": "string"}}, ["number", "body"]),
    "close_issue": (t_close_issue, "Close an issue, optionally with a closing comment.", {"number": {"type": "integer"}, "comment": {"type": "string"}}, ["number"]),
    "cluster_status": (t_cluster_status, "Live cluster health: nodes, unhealthy pods, ArgoCD apps not Synced/Healthy, firing alerts.", {}, []),
    "ask_claude": (t_ask_claude, "Hand a task to Claude Code, which can read the cluster and the GitOps repo. Use for investigations ('why is X failing?') and for ANY change "
                   "(deploy, fix, upgrade, config edit, restart). Set wants_change=true when the user wants something changed: Claude then returns a plan that the user must approve.",
                   {"task": {"type": "string", "description": "complete, self-contained description of what the user wants"},
                    "issue": {"type": "integer", "description": "related homelab/ops issue number, if any"},
                    "wants_change": {"type": "boolean"}}, ["task"]),
}
TOOL_SPECS = [{"type": "function", "function": {"name": n, "description": d, "parameters": {"type": "object", "properties": p, "required": r}}}
              for n, (_, d, p, r) in TOOLS.items()]


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


def chat(text):
    HIST.append({"role": "user", "content": text})
    del HIST[:-HISTORY]
    messages = [{"role": "system", "content": SOUL}] + HIST
    for _ in range(6):
        msg = llm(messages)
        calls = msg.get("tool_calls") or []
        messages.append({"role": "assistant", "content": msg.get("content", ""), "tool_calls": calls})
        if not calls:
            reply = msg.get("content") or "(no answer)"
            HIST.append({"role": "assistant", "content": reply})
            return reply
        for c in calls:
            name, args = c["function"]["name"], c["function"].get("arguments") or {}
            if isinstance(args, str):
                args = json.loads(args or "{}")
            log.info("tool %s %s", name, json.dumps(args)[:200])
            try:
                result = TOOLS[name][0](**args) if name in TOOLS else {"error": f"unknown tool {name}"}
            except Exception as e:  # noqa: BLE001
                result = {"error": str(e)}
            messages.append({"role": "tool", "content": json.dumps(result)[:12000]})
    return "I went in circles with my tools; please rephrase or be more specific."


# ---------------------------------------------------------------- Claude jobs
def watch_job(job_id):
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
    if meta["kind"] == "plan" and meta["wants_change"]:
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
        say(f"✅ Done: #{issue}\n\n{result}")
    save_state()


def on_button(q):
    tg("answerCallbackQuery", callback_query_id=q["id"])
    if q["from"]["id"] != ALLOWED:
        return
    action, _, pid = q.get("data", "").partition(":")
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
    threading.Thread(target=watch_job, args=(job["id"],), daemon=True).start()


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
        threading.Thread(target=watch_job, args=(job_id,), daemon=True).start()
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
    say(chat(text))


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
