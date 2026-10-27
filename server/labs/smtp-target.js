// SMTP target for Module 6 / 6.3.5 SMTP Enumeration.
//
// A genuine minimal SMTP listener (not banner theater): real TCP dialogue
// with banner, EHLO/HELO, VRFY, MAIL/RCPT/DATA, RSET/NOOP, QUIT, so Netcat
// enumeration and Nmap service detection observe true SMTP behavior.
// The exercise answer (VRFY root -> 252) comes from the protocol itself.
//
// Canonical port spec (kept HERE, not in lab.json, so the API's target
// listing can never leak the answers):
//   TCP open: 25 (only the smtp-vrfy role; decoys reuse nmap roles)
// Display convention: the SMTP host ends in .8 (see orchestrator), matching
// the established .8 role from 6.3.3.
import net from "node:net";
import { fileURLToPath } from "node:url";

export const SMTP_SLUG = "m6-6-3-5-smtp";
export const SMTP_ROLES = new Set(["smtp-vrfy"]);
export const SMTP_PORT = 25;
export const SMTP_OCTETS = { smtp: 8, decoyWhois: 22, decoyDc: 151 };

// The graded behavior: VRFY against root returns a 252 reply (classic
// sendmail wording, deterministic). Any other user -> 550. The code lives
// in the service because that IS the exercise; lab.json carries only hashes.
export const SMTP_VRFY_USER = "root";
export const SMTP_VRFY_CODE = 252;

function banner(host) {
  return `220 ${host} ESMTP Service ready`;
}

function handleLine(line, state) {
  const m = /^([A-Za-z]{4})(?:\s+(.*))?$/.exec(line.trim());
  const verb = (m ? m[1] : "").toUpperCase();
  const arg = (m ? m[2] : "") || "";
  switch (verb) {
    case "EHLO":
    case "HELO":
      state.hello = true;
      return [`250 ${state.host} greets ${arg || "unknown"}`];
    case "VRFY": {
      const user = arg.trim().replace(/^<|>$/g, "");
      if (user === SMTP_VRFY_USER) {
        return [`${SMTP_VRFY_CODE} 2.1.5 Cannot VRFY user, but will accept message and attempt delivery`];
      }
      return [`550 5.1.1 <${user || arg}>... User unknown`];
    }
    case "EXPN":
      return [`502 5.5.1 Command unimplemented`];
    case "MAIL":
      if (!/^FROM:/i.test(arg)) return [`501 5.5.2 Syntax error in MAIL command`];
      state.mail = true;
      return [`250 2.1.0 Sender ok`];
    case "RCPT":
      if (!state.mail) return [`503 5.5.1 Need MAIL command first`];
      if (!/^TO:/i.test(arg)) return [`501 5.5.2 Syntax error in RCPT command`];
      state.rcpt = true;
      return [`250 2.1.5 Recipient ok`];
    case "DATA":
      if (!state.rcpt) return [`503 5.5.1 Need RCPT command first`];
      state.data = true;
      return [`354 End data with <CR><LF>.<CR><LF>`];
    case "RSET":
      state.mail = state.rcpt = state.data = false;
      return [`250 2.0.0 Reset state`];
    case "NOOP":
      return [`250 2.0.0 OK`];
    case "QUIT":
      return [`221 2.0.0 ${state.host} closing connection`, null];
    default:
      return [`502 5.5.2 Command not recognized`];
  }
}

// role: "smtp-vrfy"
// opts: { host, ports: { tcp25 }, hostname } — ports override for loopback
// mapping (omitted entries bind ephemeral ports).
export async function startSmtpRole(role, { host = "127.0.0.1", ports = {}, hostname = "mail" } = {}) {
  if (role !== "smtp-vrfy") throw new Error(`Unknown SMTP role: ${role}`);
  const P = (k, dflt) => ports[k] ?? dflt;
  const conns = new Set();
  const srv = await new Promise((resolve, reject) => {
    // Omitted entries bind the fixed service port (the sandbox runs as
    // namespace-root, like the Docker target); loopback-mapped tests pass
    // explicit ephemeral ports.
    const s = net.createServer((conn) => {
      conns.add(conn);
      conn.on("close", () => conns.delete(conn));
      conn.on("error", () => {});
      conn.setTimeout(30000);
      conn.on("timeout", () => conn.destroy());
      const state = { host: hostname, hello: false, mail: false, rcpt: false, data: false, dataBuf: "" };
      try { conn.write(banner(state.host) + "\r\n"); } catch {}
      let buf = "";
      conn.on("data", (d) => {
        buf += d.toString("utf8");
        // DATA phase consumes lines until a lone dot.
        if (state.data) {
          const lines = buf.split("\r\n");
          buf = lines.pop();
          for (const ln of lines) {
            if (ln === ".") {
              state.data = false;
              state.mail = state.rcpt = false;
              try { conn.write(`250 2.0.0 Message accepted\r\n`); } catch {}
            }
          }
          if (buf.length > 65536) conn.destroy();
          return;
        }
        // Command phase: one reply per CRLF-terminated line.
        const parts = buf.split("\r\n");
        buf = parts.pop();
        // Tolerate bare-LF clients (netcat pastes) without changing replies.
        const pending = [];
        for (const p of parts) pending.push(...p.split("\n"));
        if (buf.includes("\n")) {
          const tail = buf.split("\n");
          buf = tail.pop();
          pending.push(...tail);
        }
        for (let ln of pending) {
          ln = ln.replace(/\r$/, "");
          if (!ln) continue;
          if (ln.length > 512) {
            try { conn.write(`500 5.5.2 Line too long\r\n`); } catch {}
            continue;
          }
          for (const rep of handleLine(ln, state)) {
            if (rep === null) {
              try { conn.end(); } catch {}
              return;
            }
            try { conn.write(rep + "\r\n"); } catch {}
          }
        }
        if (buf.length > 4096) conn.destroy();
      });
    });
    s.on("error", reject);
    s.listen(P("tcp25", SMTP_PORT), host, () => resolve(s));
  });
  return {
    role,
    ports: [srv.address().port],
    close: async () => {
      for (const c of conns) { try { c.destroy(); } catch {} }
      conns.clear();
      await new Promise((r) => srv.close(r)).catch(() => {});
    },
  };
}

// Standalone entrypoint (used by the Docker image).
//   TARGET_ROLE=smtp-vrfy  TARGET_HOST=0.0.0.0  [fixed ports]
const invokedAsMain = (() => {
  try { return process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]; } catch { return false; }
})();
if (invokedAsMain) {
  const role = process.env.TARGET_ROLE || "";
  const fixed = process.env.TARGET_FIXED_PORTS === "1";
  if (!SMTP_ROLES.has(role)) {
    console.error("TARGET_ROLE must be smtp-vrfy");
    process.exit(1);
  }
  startSmtpRole(role, {
    host: process.env.TARGET_HOST || "0.0.0.0",
    ports: { tcp25: fixed ? SMTP_PORT : 0 },
    hostname: process.env.TARGET_HOSTNAME || "mail",
  })
    .then(() => console.log(`axiom-lab-smtp target role=${role} listening`))
    .catch((e) => { console.error("smtp target failed to start", e?.message || e); process.exit(1); });
}
