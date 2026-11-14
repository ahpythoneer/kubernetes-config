// claude-runner: runs Claude Code headless jobs for chat-ops (homelab/ops#19).
//
// Hermes (namespace hermes-agent) is the only client. Every request needs
// "Authorization: Bearer <secret/chatops/runner token>". Jobs run one at a time in the
// shared code-server workspace (~/work/kubernetes-config), so the user can open the same
// files in code-server.
//
//   mode "plan"    : read-only tools only; Claude investigates and returns a plan
//   mode "execute" : runs an APPROVED plan; may edit files, commit/push to git and use the
//                    few kubectl write verbs allowed by RBAC (ClusterRole chatops-executor)
//
// Tools a mode does not allow are refused automatically: headless Claude cannot ask anyone.
//
// API: GET /healthz | POST /v1/jobs {mode, task, issue?, plan?} | GET /v1/jobs[/:id[?since=n]]
//      POST /v1/jobs/:id/cancel
'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn, execFileSync } = require('child_process');

const PORT = 8787;
const HOME = '/home/coder';
const SECRETS = '/vault/secrets';
const TOOLS = `${HOME}/.local/share/chatops-tools`;
const CLAUDE = `${TOOLS}/claude-${process.env.CLAUDE_VERSION}`;
const REPO = `${HOME}/work/kubernetes-config`;
const REPO_URL = 'https://github.com/ahpythoneer/kubernetes-config.git';
const JOB_DIR = `${HOME}/.chatops/jobs`;
const RULES = fs.readFileSync('/runner/rules.md', 'utf8');
const TIMEOUT_MS = { plan: 15 * 60e3, execute: 45 * 60e3 };
const MAX_EVENTS = 400;

const READ_ONLY = [
  'Read', 'Grep', 'Glob', 'LS', 'TodoWrite',
  'Bash(git status:*)', 'Bash(git log:*)', 'Bash(git diff:*)', 'Bash(git show:*)',
  'Bash(git fetch:*)', 'Bash(git branch:*)', 'Bash(git rev-parse:*)',
  'Bash(kubectl get:*)', 'Bash(kubectl describe:*)', 'Bash(kubectl logs:*)',
  'Bash(kubectl top:*)', 'Bash(kubectl events:*)', 'Bash(kubectl explain:*)',
  'Bash(kubectl rollout status:*)', 'Bash(kubectl rollout history:*)',
  'Bash(kubectl kustomize:*)', 'Bash(kubectl diff:*)', 'Bash(kubectl api-resources:*)',
  'Bash(kubectl apply --dry-run=server:*)', 'Bash(kubectl auth can-i:*)',
  'Bash(ls:*)', 'Bash(wc:*)', 'Bash(date:*)',
];
// Shell readers (cat/head/grep/diff...) are deliberately absent: they could print the Vault files or
// the environment. Claude's own Read/Grep/Glob tools are path-checked against DENY instead.
const DENY = [
  'Read(//vault/**)', 'Read(//proc/**)', 'Read(//var/run/secrets/**)', 'Read(//run/secrets/**)',
  'Read(//home/coder/.claude-runner/**)', 'Read(//home/coder/.config/**)', 'Read(//home/coder/.local/**)',
  'Bash(env:*)', 'Bash(printenv:*)', 'Bash(set:*)', 'Bash(kubectl get secret:*)', 'Bash(kubectl get secrets:*)',
];
const WRITE = [
  'Edit', 'MultiEdit', 'Write',
  'Bash(git add:*)', 'Bash(git commit:*)', 'Bash(git push:*)', 'Bash(git pull:*)',
  'Bash(git switch:*)', 'Bash(git checkout:*)', 'Bash(git restore:*)', 'Bash(git stash:*)',
  'Bash(git mv:*)', 'Bash(git rm:*)', 'Bash(mkdir:*)',
  'Bash(kubectl rollout restart:*)', 'Bash(kubectl delete pod:*)', 'Bash(kubectl create job:*)',
  'Bash(kubectl annotate:*)', 'Bash(kubectl wait:*)',
];
const TOOLS_FOR = { plan: READ_ONLY, execute: READ_ONLY.concat(WRITE) };

const secret = (name) => fs.readFileSync(path.join(SECRETS, name), 'utf8').trim();
const now = () => new Date().toISOString();
const log = (...a) => console.log(now(), ...a);
fs.mkdirSync(JOB_DIR, { recursive: true });

// ---------------------------------------------------------------- jobs
const jobs = new Map();
const queue = [];
let running = null;

function prepareRepo() {
  const git = (...args) => execFileSync('git', args, { cwd: REPO, encoding: 'utf8' }).trim();
  if (!fs.existsSync(`${REPO}/.git`)) {
    fs.mkdirSync(path.dirname(REPO), { recursive: true });
    execFileSync('git', ['clone', '--quiet', REPO_URL, REPO]);
  }
  // the push credential comes from the Vault-rendered file at use time; it is never written to disk here
  git('config', 'credential.https://github.com.helper',
    '!f() { test "$1" = get && echo username=x-access-token && echo "password=$(cat /vault/secrets/github-token)"; }; f');
  git('config', 'user.name', 'Claude (chat-ops)');
  git('config', 'user.email', 'claude-bot@racktocloud.com');
  git('fetch', '--quiet', 'origin');
  const status = git('status', '--porcelain');
  const branch = git('rev-parse', '--abbrev-ref', 'HEAD');
  if (!status && branch === 'main') git('merge', '--quiet', '--ff-only', 'origin/main');
  return { branch, dirty: status ? status.split('\n').slice(0, 30) : [], head: git('rev-parse', '--short', 'HEAD') };
}

function buildPrompt(job, repo) {
  const ref = job.issue ? `homelab/ops#${job.issue}` : '(no issue)';
  const state = repo.dirty.length
    ? `The working tree has UNCOMMITTED changes (possibly the user's own edits in code-server). Do not discard them:\n${repo.dirty.join('\n')}`
    : 'The working tree is clean.';
  const head = `Tracking issue: ${ref}\nRepository: ${REPO} (branch ${repo.branch}, HEAD ${repo.head}). ${state}\n\n`;
  if (job.mode === 'plan') {
    return head + `MODE: PLAN ONLY. Investigate read-only and reply with a short numbered plan: exact files, commands and verification, plus risks. Do not change anything.\n\nRequest from the user:\n${job.task}`;
  }
  return head + `MODE: EXECUTE. The user APPROVED the plan below. Carry it out, verify, and finish with a short report (what changed, commit SHAs, how it was verified, follow-ups). If reality differs from the plan in a way that changes risk, stop and explain instead.\n\nRequest from the user:\n${job.task}\n\nApproved plan:\n${job.plan || '(none given: keep the change minimal and exactly as requested)'}`;
}

function pushEvent(job, ev) {
  job.events.push({ n: job.eventCount++, t: now(), ...ev });
  if (job.events.length > MAX_EVENTS) job.events.splice(0, job.events.length - MAX_EVENTS);
}

function handleLine(job, line) {
  let m;
  try { m = JSON.parse(line); } catch { return; }
  if (m.type === 'assistant') {
    for (const c of m.message?.content || []) {
      if (c.type === 'text' && c.text.trim()) pushEvent(job, { type: 'text', text: c.text.slice(0, 4000) });
      if (c.type === 'tool_use') {
        const i = c.input || {};
        pushEvent(job, { type: 'tool', tool: c.name, detail: String(i.command || i.file_path || i.pattern || i.description || '').slice(0, 300) });
      }
    }
  } else if (m.type === 'user') {
    for (const c of m.message?.content || []) {
      if (c.type === 'tool_result' && c.is_error) pushEvent(job, { type: 'denied_or_error', text: String(typeof c.content === 'string' ? c.content : JSON.stringify(c.content)).slice(0, 300) });
    }
  } else if (m.type === 'result') {
    job.result = (m.result || '').slice(0, 20000);
    job.isError = !!m.is_error;
    job.costUsd = m.total_cost_usd;
    job.turns = m.num_turns;
  }
}

function finish(job, status) {
  if (job.finished) return;
  job.status = status;
  job.finished = now();
  clearTimeout(job.timer);
  try { job.headAfter = execFileSync('git', ['rev-parse', '--short', 'HEAD'], { cwd: REPO, encoding: 'utf8' }).trim(); } catch {}
  const { proc, timer, ...record } = job;
  fs.writeFileSync(`${JOB_DIR}/${job.id}.json`, JSON.stringify(record, null, 1));
  log(`job ${job.id} ${status} (${job.mode}, issue ${job.issue || '-'}, ${job.turns || 0} turns)`);
  running = null;
  setImmediate(next);
}

function next() {
  if (running || !queue.length) return;
  const job = queue.shift();
  running = job;
  job.status = 'running';
  job.started = now();
  let repo;
  try { repo = prepareRepo(); } catch (e) { job.result = `repo preparation failed: ${e.message}`; return finish(job, 'failed'); }
  job.headBefore = repo.head;
  const args = ['-p', '--output-format', 'stream-json', '--verbose',
    '--max-turns', job.mode === 'plan' ? '40' : '80',
    '--append-system-prompt', RULES,
    '--disallowedTools', ...DENY,
    '--allowedTools', ...TOOLS_FOR[job.mode]];
  const env = {
    PATH: `${TOOLS}/bin:/usr/local/bin:/usr/bin:/bin`,
    HOME, CLAUDE_CONFIG_DIR: `${HOME}/.claude-runner`,
    CLAUDE_CODE_OAUTH_TOKEN: secret('claude-token'),
    KUBERNETES_SERVICE_HOST: process.env.KUBERNETES_SERVICE_HOST,
    KUBERNETES_SERVICE_PORT: process.env.KUBERNETES_SERVICE_PORT,
    DISABLE_AUTOUPDATER: '1', CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: '1',
  };
  const proc = spawn(CLAUDE, args, { cwd: REPO, env, stdio: ['pipe', 'pipe', 'pipe'] });
  job.proc = proc;
  proc.stdin.end(buildPrompt(job, repo));
  let buf = '';
  proc.stdout.on('data', (d) => {
    buf += d;
    let i;
    while ((i = buf.indexOf('\n')) >= 0) { handleLine(job, buf.slice(0, i)); buf = buf.slice(i + 1); }
  });
  proc.stderr.on('data', (d) => pushEvent(job, { type: 'stderr', text: String(d).slice(0, 500) }));
  proc.on('close', (code) => finish(job, job.status === 'cancelled' ? 'cancelled'
    : job.status === 'timeout' ? 'timeout' : (code === 0 && !job.isError ? 'done' : 'failed')));
  job.timer = setTimeout(() => { job.status = 'timeout'; proc.kill('SIGTERM'); }, TIMEOUT_MS[job.mode]);
}

// ---------------------------------------------------------------- http
function authorized(req) {
  const want = Buffer.from(`Bearer ${secret('runner-token')}`);
  const got = Buffer.from(req.headers.authorization || '');
  return got.length === want.length && crypto.timingSafeEqual(got, want);
}
const view = ({ proc, timer, ...j }, since = 0) => ({ ...j, events: j.events.filter((e) => e.n >= since) });
function send(res, code, obj) { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); }

http.createServer((req, res) => {
  const url = new URL(req.url, 'http://x');
  if (url.pathname === '/healthz') {
    return send(res, 200, { ok: true, claude: fs.existsSync(CLAUDE), repo: fs.existsSync(`${REPO}/.git`), running: running?.id || null, queued: queue.length });
  }
  if (!authorized(req)) return send(res, 401, { error: 'unauthorized' });
  const m = url.pathname.match(/^\/v1\/jobs(?:\/([a-f0-9]{12}))?(\/cancel)?$/);
  if (!m) return send(res, 404, { error: 'not found' });
  const [, id, cancel] = m;
  if (req.method === 'GET' && !id) {
    return send(res, 200, [...jobs.values()].slice(-20).map((j) => ({ id: j.id, mode: j.mode, issue: j.issue, status: j.status, created: j.created })));
  }
  if (req.method === 'GET' && id) {
    let j = jobs.get(id);
    // finished jobs survive a runner restart as their record on the volume
    if (!j && fs.existsSync(`${JOB_DIR}/${id}.json`)) j = JSON.parse(fs.readFileSync(`${JOB_DIR}/${id}.json`, 'utf8'));
    return j ? send(res, 200, view(j, Number(url.searchParams.get('since') || 0))) : send(res, 404, { error: 'no such job' });
  }
  if (req.method === 'POST' && id && cancel) {
    const j = jobs.get(id);
    if (!j) return send(res, 404, { error: 'no such job' });
    if (j.status === 'queued') { queue.splice(queue.indexOf(j), 1); finish(j, 'cancelled'); }
    else if (j.status === 'running') { j.status = 'cancelled'; j.proc.kill('SIGTERM'); }
    return send(res, 200, { id, status: j.status });
  }
  if (req.method === 'POST' && !id) {
    let body = '';
    req.on('data', (d) => { body += d; if (body.length > 200e3) req.destroy(); });
    req.on('end', () => {
      let b;
      try { b = JSON.parse(body); } catch { return send(res, 400, { error: 'bad json' }); }
      if (!['plan', 'execute'].includes(b.mode) || !b.task) return send(res, 400, { error: 'need mode plan|execute and task' });
      const job = { id: crypto.randomBytes(6).toString('hex'), mode: b.mode, task: String(b.task).slice(0, 20000),
        plan: b.plan ? String(b.plan).slice(0, 20000) : null, issue: b.issue ? Number(b.issue) : null,
        status: 'queued', created: now(), events: [], eventCount: 0 };
      jobs.set(job.id, job);
      queue.push(job);
      log(`job ${job.id} queued (${job.mode}, issue ${job.issue || '-'})`);
      setImmediate(next);
      return send(res, 202, { id: job.id, status: job.status, position: queue.length });
    });
    return;
  }
  return send(res, 405, { error: 'method not allowed' });
}).listen(PORT, () => log(`claude-runner listening on :${PORT}, claude ${process.env.CLAUDE_VERSION}`));
