// Init step for claude-runner: download pinned tool binaries into the code-server volume,
// verify their SHA-256, and skip the download when a verified copy is already cached.
'use strict';
const fs = require('fs');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

const DIR = '/home/coder/.local/share/chatops-tools';
const TOOLS = [
  { name: `claude-${process.env.CLAUDE_VERSION}`, link: 'claude', sha256: process.env.CLAUDE_SHA256,
    url: `https://downloads.claude.ai/claude-code-releases/${process.env.CLAUDE_VERSION}/linux-x64/claude` },
  { name: `kubectl-${process.env.KUBECTL_VERSION}`, link: 'kubectl', sha256: process.env.KUBECTL_SHA256,
    url: `https://dl.k8s.io/release/${process.env.KUBECTL_VERSION}/bin/linux/amd64/kubectl` },
];

const sha = (f) => crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex');
fs.mkdirSync(`${DIR}/bin`, { recursive: true });
for (const t of TOOLS) {
  const dest = `${DIR}/${t.name}`;
  if (fs.existsSync(dest) && sha(dest) === t.sha256) {
    console.log(`${t.name}: cached, checksum ok`);
  } else {
    console.log(`${t.name}: downloading ${t.url}`);
    execFileSync('curl', ['-fsSL', '--retry', '3', '-o', `${dest}.tmp`, t.url], { stdio: 'inherit' });
    const got = sha(`${dest}.tmp`);
    if (got !== t.sha256) { fs.unlinkSync(`${dest}.tmp`); throw new Error(`${t.name}: checksum mismatch (${got})`); }
    fs.chmodSync(`${dest}.tmp`, 0o755);
    fs.renameSync(`${dest}.tmp`, dest);
    console.log(`${t.name}: installed, checksum ok`);
  }
  const link = `${DIR}/bin/${t.link}`;
  try { fs.unlinkSync(link); } catch {}
  fs.symlinkSync(dest, link);
}
// drop older versions so the volume does not fill up with 366 MB binaries
for (const f of fs.readdirSync(DIR)) {
  if (f !== 'bin' && !TOOLS.some((t) => t.name === f)) { fs.rmSync(`${DIR}/${f}`, { force: true }); console.log(`removed old ${f}`); }
}
