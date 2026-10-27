// SMB range for Module 6 / 6.3.4 SMB Enumeration.
//
// Canonical spec shared by every provider: the Docker image (lab-images/m6/
// smb-634, real Samba smbd) and the local sandbox (impacket smbserver.py for
// transport + share metadata) both derive from HERE, so share names, share
// comments, and the dc01/admin-share contract are identical everywhere.
//
// Roles:
//   smb        — generic SMB host: one [public] guest share (445 only)
//   smb-dc     — dc01 (.151): [ADMIN$] + [C$] guest shares (IPC$ is automatic)
//   smb-alfred — Topic Exercise host: [users] (names local user alfred) +
//                [backup] (its comment carries the per-instance flag)
// Decoys (no 445) reuse the 6.3.3 nmap-target roles (smtp/whois) unchanged.
//
// Secrets: NOTHING answer-bearing is baked in. The alfred flag arrives as a
// runtime argument (FLAG_SMB env for smbd; flags.smb for impacket) minted per
// instance like the 6.3.3 runtime flags.
//
// Fidelity note: genuine Samba smbd implements the full exercise (Nmap 445
// count, smbclient -L, `net view`, enum4linux incl. SAMR/RID user cycling for
// alfred). The local impacket path speaks real SMB (same Nmap/smbclient/
// enum4linux-share observable behavior) but impacket has no SAMR server, so
// local user discovery goes through enum4linux share enumeration (the
// [users] comment names alfred) rather than RID cycling. Docker is the exact
// path; local is partial by tool availability, never by faked output.
import net from "node:net";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { spawn, execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

export const SMB_SLUG = "m6-6-3-4-smb";
// Display octets inside the isolated /24. Exactly the ten smb* roles expose
// TCP/445; decoy octets expose only their own discovery ports (25/43).
export const SMB_OCTETS = {
  walk: [11, 12, 13, 14, 15, 16],
  topic: [60, 61, 62],
  alfred: 61,
  dc: 151,
  decoySmtp: 21,
  decoyWhois: 22,
};
export const SMB_ROLES = new Set(["smb", "smb-dc", "smb-alfred"]);
export const SMB_PORT = 445;
export const SMB_FLAG_PLACEHOLDER = "AXIOM{unprovisioned}";

// ---------------------------------------------------------------- shares
// Share inventory per role. Comments are the exercise surface: dc01 carries
// exactly the three historical admin shares; the alfred host names the local
// user in [users] and the per-instance flag in [backup].
export function shareSpecs(role, flag = SMB_FLAG_PLACEHOLDER) {
  if (role === "smb-dc") {
    return [
      { name: "ADMIN$", comment: "Remote Admin" },
      { name: "C$", comment: "Default share" },
    ];
  }
  if (role === "smb-alfred") {
    return [
      { name: "users", comment: "Home directories - contact alfred" },
      { name: "backup", comment: `Nightly backups - flag: ${flag}` },
    ];
  }
  if (role === "smb") {
    return [{ name: "public", comment: "Public file share" }];
  }
  throw new Error(`Unknown SMB role: ${role}`);
}

// ------------------------------------------------------------ smb.conf
// Standalone-server smbd config. 445 only (no NetBIOS), guest-readable
// shares, null sessions allowed so anonymous enumeration works the way the
// documented enum4linux/net-view workflow expects.
export function buildSmbConf(role, { host = "0.0.0.0", flag = SMB_FLAG_PLACEHOLDER, stateDir = "/tmp/samba", shareRoot = "/srv/shares" } = {}) {
  const shares = shareSpecs(role, flag);
  const lines = [
    "[global]",
    "  workgroup = AXIOMLAB",
    "  server string = axiom lab smb target",
    "  server role = standalone server",
    "  map to guest = Bad User",
    "  restrict anonymous = 0",
    "  smb ports = 445",
    "  disable netbios = yes",
    `  interfaces = ${host}`,
    "  bind interfaces only = yes",
    `  private dir = ${stateDir}/private`,
    `  lock directory = ${stateDir}/lock`,
    `  state directory = ${stateDir}/lib`,
    `  cache directory = ${stateDir}/cache`,
    `  log file = ${stateDir}/log/smbd.log`,
    `  pid directory = ${stateDir}`,
    `  passdb backend = tdbsam:${stateDir}/private/passdb.tdb`,
    "  guest account = nobody",
    "  disable spoolss = yes",
    "  load printers = no",
    "  printcap name = /dev/null",
    "",
  ];
  for (const s of shares) {
    lines.push(
      `[${s.name}]`,
      `  path = ${shareRoot}/${s.name.replace(/\$$/, "").toLowerCase() || "share"}`,
      `  comment = ${s.comment}`,
      "  guest ok = yes",
      "  read only = yes",
      ""
    );
  }
  return lines.join("\n");
}

// ------------------------------------------------------------ net view
// `net view` compatibility shim for the Linux attacker shell. Windows has
// `net view \\HOST`; Samba's own `net` has no `view` subcommand, so this
// translates the documented workflow into a LIVE `smbclient -L` query and
// prints Windows-style output. Enumeration is genuine (live SMB query,
// live failures); only the presentation matches the documented command.
// Every other `net` invocation passes through to the real Samba `net`.
export const NET_VIEW_SHIM = `#!/bin/sh
# Axiom 'net view' shim: documented Windows workflow over real Samba tooling.
#   net view \\\\<host>   share enumeration via live smbclient -L
# Anything else delegates to the real Samba net (/usr/bin/net).
if [ "$1" != "view" ] && [ "$1" != "VIEW" ]; then
  exec /usr/bin/net "$@"
fi
shift
HOST=""
for a in "$@"; do
  case "$a" in
    /ALL|/all|-h|--help) echo "Usage: net view \\\\\\\\<host>"; exit 0;;
    *) HOST="$a";;
  esac
done
HOST=$(printf '%s' "$HOST" | sed -e 's#^[\\\\/]*##' -e 's#[\\\\/]*$##')
if [ -z "$HOST" ]; then
  echo "Usage: net view \\\\\\\\<host>   (for example: net view \\\\\\\\dc01)"
  exit 1
fi
RAW=$(smbclient -L "//$HOST" -N 2>&1)
if ! printf '%s' "$RAW" | grep -qi '^[[:space:]]*Sharename'; then
  echo "System error 53 has occurred."
  echo "The network path was not found."
  exit 1
fi
printf 'Shared resources at \\\\\\\\%s\\n\\n' "$HOST"
printf '%-12s %-8s %s\\n' "Share name" "Type" "Comment"
printf '%-12s %-8s %s\\n' "----------" "----" "-------"
printf '%s' "$RAW" | awk '
  BEGIN { head = 0 }
  /^[[:space:]]*Sharename/ { head = 1; next }
  head == 0 { next }
  /^[[:space:]]*-+([[:space:]]+-+)+[[:space:]]*$/ { next }
  /^[[:space:]]*$/ { exit }
  /^Server|^Workgroup|^SMB1/ { exit }
  {
    line = $0; sub(/^[ \\t]+/, "", line);
    n = split(line, f, /[ \\t][ \\t]+/);
    if (n < 2) next;
    name = f[1]; type = f[2]; comment = "";
    if (n > 2) { comment = f[3]; for (i = 4; i <= n; i++) comment = comment " " f[i]; }
    if (name == "IPC$") type = "IPC";
    printf "%-12s %-8s %s\\n", name, type, comment;
  }' | sort
printf '\\nThe command completed successfully.\\n'
`;

// ------------------------------------------------------------ hosts file
// Name resolution for the range (dc01 in particular). The sandbox bind-
// mounts this over /etc/hosts inside its mount namespace; Docker uses
// --network-alias for the same names. Host files outside the lab are
// never touched.
export function buildHostsFile(entries) {
  const lines = ["127.0.0.1 localhost", "::1 localhost"];
  for (const e of entries || []) {
    if (e?.ip && e?.name) lines.push(`${e.ip} ${e.name}`);
  }
  return lines.join("\n") + "\n";
}

// ------------------------------------------------------------ impacket
// Local-provider SMB: ONE impacket server process per lab IP serving every
// share of that host (single 445 bind — multi-share hosts never contend
// with themselves). Returns a {close} handle like the Node role starters.
// Requires an impacket-capable python3 on PATH (documented local-provider
// requirement alongside unshare/ip/node/nmap).
function impacketPython() {
  const cands = ["/usr/bin/python3", "/usr/bin/python", "python3"];
  for (const c of cands) {
    try {
      execFileSync(c, ["-c", "import impacket.smbserver"], { timeout: 15000 });
      return c;
    } catch { /* try next */ }
  }
  return "";
}

export async function launchImpacketShares(role, { ip = "127.0.0.1", flag = SMB_FLAG_PLACEHOLDER, workdir = "" } = {}) {
  const py = impacketPython();
  if (!py) throw new Error("impacket not found (need a python3 with impacket for local SMB labs).");
  const root = workdir || fs.mkdtempSync(path.join(os.tmpdir(), "axiom-smb-"));
  const dir = path.join(root, role);
  fs.mkdirSync(dir, { recursive: true });
  const specs = shareSpecs(role, flag).map((s) => {
    const shareDir = path.join(dir, s.name.replace(/\$$/, "").toLowerCase() || "share");
    fs.mkdirSync(shareDir, { recursive: true });
    return { name: s.name, path: shareDir, comment: s.comment };
  });
  fs.writeFileSync(path.join(dir, "shares.json"), JSON.stringify(specs));
  const script = new URL("./smb-impacket-server.py", import.meta.url).pathname;
  const child = spawn(py, [script, ip, dir], { stdio: "ignore" });
  // Readiness: every share answers `smbclient -L` (share table present).
  const deadline = Date.now() + 30000;
  for (;;) {
    try {
      const out = execFileSync("smbclient", ["-L", `//${ip}`, "-p", String(SMB_PORT), "-N"],
        { encoding: "utf8", timeout: 8000 });
      if (/Sharename/.test(out)) break;
    } catch { /* not ready yet */ }
    if (Date.now() > deadline) {
      try { child.kill("SIGKILL"); } catch {}
      throw new Error(`Impacket SMB shares did not become ready on ${ip}.`);
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  return {
    role,
    close: async () => {
      try { child.kill("SIGKILL"); } catch {}
    },
  };
}

export function tcpProbe(host, port, timeoutMs = 3000) {
  return new Promise((resolve) => {
    const sock = new net.Socket();
    const timer = setTimeout(() => { sock.destroy(); resolve(false); }, timeoutMs);
    sock.on("error", () => { clearTimeout(timer); resolve(false); });
    sock.connect(port, host, () => { clearTimeout(timer); sock.destroy(); resolve(true); });
  });
}

// Standalone entrypoint (used by the smb-634 Docker image, which runs as
// container-root because smbd manages access tokens and cannot run
// unprivileged — see the image Dockerfile).
//   TARGET_ROLE=smb|smb-dc|smb-alfred  TARGET_HOST=0.0.0.0  FLAG_SMB=...
const invokedAsMain = (() => {
  try { return process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]; } catch { return false; }
})();
if (invokedAsMain) {
  const role = process.env.TARGET_ROLE || "";
  if (!SMB_ROLES.has(role)) {
    console.error("TARGET_ROLE must be smb|smb-dc|smb-alfred");
    process.exit(1);
  }
  const host = process.env.TARGET_HOST || "0.0.0.0";
  const flag = process.env.FLAG_SMB || SMB_FLAG_PLACEHOLDER;
  const stateDir = "/tmp/samba";
  const shareRoot = "/srv/shares";
  for (const sub of ["private", "lock", "lib", "cache", "log"]) {
    fs.mkdirSync(path.join(stateDir, sub), { recursive: true });
  }
  const conf = buildSmbConf(role, { host, flag, stateDir, shareRoot });
  fs.writeFileSync(path.join(stateDir, "smb.conf"), conf);
  for (const s of shareSpecs(role, flag)) {
    fs.mkdirSync(path.join(shareRoot, s.name.replace(/\$$/, "").toLowerCase() || "share"), { recursive: true });
  }
  const setup = [];
  if (role === "smb-alfred") {
    // Local account for SAMR/RID user enumeration (guest shares stay
    // anonymous; the account simply exists in tdbsam like the source lab).
    setup.push(`id alfred >/dev/null 2>&1 || useradd -M -s /usr/sbin/nologin alfred`);
    setup.push(`printf '%s\\n%s\\n' "$ALFRED_PW" "$ALFRED_PW" | smbpasswd -a -s -c ${stateDir}/smb.conf alfred >/dev/null 2>&1`);
  }
  (async () => {
    try {
      const pw = (await import("node:crypto")).randomBytes(12).toString("hex");
      for (const cmd of setup) {
        execFileSync("sh", ["-c", cmd], { env: { ...process.env, ALFRED_PW: pw }, timeout: 30000 });
      }
      const smbd = spawn("smbd", ["-F", "--no-process-group", "-s", path.join(stateDir, "smb.conf")], { stdio: "inherit" });
      console.log(`axiom-lab-smb target role=${role} listening`);
      smbd.on("exit", (code) => process.exit(code ?? 1));
    } catch (e) {
      console.error("smb target failed to start", e?.message || e);
      process.exit(1);
    }
  })();
}
