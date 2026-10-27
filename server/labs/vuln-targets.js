// Scanner targets for Module 7.2 (7.2.3–7.2.6) vulnerability-scanning labs.
//
// Real multi-service listeners (not finding theater): genuine HTTP
// services with observable Server headers and behaviors the Axiom scanner
// actually interrogates (Apache 2.4.49 traversal response, Jetty version
// header, linked web-application graphs for real crawling). Findings are
// derived from probe results by the scanner engine — never pre-written.
//
// Roles (per-target personalities selected by TARGET_ROLE):
//   scan-apache — TCP/80 Apache/2.4.49 (+ traversal behavior),
//                 TCP/9999 webapp graph A, SSH served by the sidecar
//                 paramiko server (see vuln-ssh-server.py)
//   scan-jetty  — TCP/8080 Jetty(9.4.43.v20210629), TCP/9999 webapp graph B
//   scan-web-a  — TCP/80 plain, TCP/9999 webapp graph C
//   scan-web-b  — TCP/80 plain, TCP/9999 webapp graph D (flag page inside;
//                 per-instance flag via FLAG_723, like the 6.3.3 pattern)
//
// Canonical behavior: this module is the behavior for every provider. The
// Docker image copies it verbatim; the local provider runs it in-process.
// Nothing answer-bearing is baked in: versions/behaviors are the exercise
// surface (students must observe them), and the flag arrives at runtime.
import http from "node:http";
import net from "node:net";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

export const VULN_SLUG_PREFIX = "m7-7-2-";
export const SCAN_ROLES = new Set(["scan-apache", "scan-jetty", "scan-web-a", "scan-web-b"]);
export const APACHE_VERSION = "Apache/2.4.49 (Unix)";
export const JETTY_VERSION = "Jetty(9.4.43.v20210629)";
export const TRAVERSAL_MARKER = "root:x:0:0:root:";

const PASSWD_EXCERPT = [
  "root:x:0:0:root:/root:/bin/bash",
  "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
  "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
  "",
].join("\n");

function page(title, heading, bodyLinks, extra = "") {
  const links = bodyLinks.map(([href, text]) => `<li><a href="${href}">${text}</a></li>`).join("\n");
  return [
    `<!DOCTYPE html>`,
    `<html>`,
    `<head><title>${title}</title></head>`,
    `<body>`,
    `<h1>${heading}</h1>`,
    `<ul>`,
    links,
    `</ul>`,
    extra,
    `</body>`,
    `</html>`,
    ``,
  ].join("\n");
}

// Webapp graphs per role. Links are relative; the crawler must resolve,
// normalize, dedupe, and recurse them. Only graph D contains the flag,
// injected at runtime (never baked in).
function webappGraph(role, flag) {
  if (role === "scan-apache") {
    return {
      "/": page("Intranet Home", "Intranet Home", [["/about", "About"], ["/docs", "Documents"]]),
      "/about": page("About", "About this host", [["/", "Home"]]),
      "/docs": page("Documents", "Documents", [["/docs/setup", "Setup guide"], ["/", "Home"]]),
      "/docs/setup": page("Setup guide", "Setup guide", [["/docs", "Documents"]]),
    };
  }
  if (role === "scan-jetty") {
    return {
      "/": page("Status", "Service status", [["/status", "Detailed status"], ["/help", "Help"]]),
      "/status": page("Detailed status", "Detailed status", [["/status/details", "More detail"], ["/", "Status"]]),
      "/status/details": page("More detail", "More detail", [["/status", "Detailed status"]]),
      "/help": page("Help", "Help", [["/", "Status"]]),
    };
  }
  if (role === "scan-web-a") {
    return {
      "/": page("Blog", "Blog", [["/blog", "All posts"], ["/contact", "Contact"]]),
      "/blog": page("All posts", "All posts", [["/blog/post-1", "First post"], ["/blog/post-2", "Second post"], ["/", "Blog"]]),
      "/blog/post-1": page("First post", "First post", [["/blog", "All posts"]]),
      "/blog/post-2": page("Second post", "Second post", [["/blog", "All posts"]]),
      "/contact": page("Contact", "Contact", [["/", "Blog"]]),
    };
  }
  // scan-web-b: the flag lives in a page three links deep from /.
  return {
    "/": page("News", "News", [["/articles", "Articles"], ["/search", "Search"]]),
    "/articles": page("Articles", "Articles", [["/articles/news", "News"], ["/articles/old-backup", "Old backup"], ["/", "News"]]),
    "/articles/news": page("News", "News", [["/articles", "Articles"]]),
    "/articles/old-backup": page(
      "Old backup", "Old backup",
      [["/articles", "Articles"]],
      `<p>Retired export, kept for reference.</p>\n<p>flag: ${flag || "AXIOM{unprovisioned}"}</p>\n`
    ),
    "/search": page("Search", "Search", [["/", "News"]]),
  };
}

function isTraversalProbe(rawUrl) {
  const u = String(rawUrl || "");
  // CVE-2021-41773 style: encoded dot segments bypassing the path filter.
  return /%2e/i.test(u) || /(^|\/)\.(\/|$)/.test(u);
}

function apacheHandler(req, res) {
  res.setHeader("Server", APACHE_VERSION);
  if (isTraversalProbe(req.url) && req.url !== "/") {
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end(PASSWD_EXCERPT);
    return;
  }
  res.writeHead(200, { "Content-Type": "text/html" });
  res.end(page("Intranet", "Intranet", []));
}

function jettyHandler(req, res) {
  res.setHeader("Server", JETTY_VERSION);
  res.writeHead(200, { "Content-Type": "text/html" });
  res.end(page("Welcome to Jetty", "Welcome to Jetty", []));
}

function plainHandler(serverName) {
  return (req, res) => {
    res.setHeader("Server", serverName);
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end(page("Home", "Home", []));
  };
}

function webappHandler(graph) {
  return (req, res) => {
    res.setHeader("Server", "AxiomScan/1.0");
    const path = String(req.url || "/").split("?")[0];
    const body = graph[path];
    if (!body) {
      res.writeHead(404, { "Content-Type": "text/html" });
      res.end(page("Not found", "Not found", [["/", "Home"]]));
      return;
    }
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end(body);
  };
}

function listenHttp(host, port, handler, conns) {
  return new Promise((resolve, reject) => {
    const srv = http.createServer((req, res) => {
      try { handler(req, res); } catch { try { res.writeHead(500); res.end(); } catch {} }
    });
    srv.on("error", reject);
    srv.on("connection", (c) => {
      conns.add(c);
      c.on("close", () => conns.delete(c));
    });
    srv.listen(port, host, () => resolve(srv));
  });
}

// role: one of SCAN_ROLES.
// opts: { host, ports: { http80, http8080, http9999 }, flag, ssh: {user,
//   password, port} } — omitted ports bind ephemeral ports (loopback
//   mapping); fixed ports are passed explicitly by providers. When ssh is
//   provided and the role serves SSH (scan-apache), a paramiko sidecar is
//   spawned for genuine SSH password authentication.
export async function startScanRole(role, { host = "127.0.0.1", ports = {}, flag = "", ssh = null } = {}) {
  if (!SCAN_ROLES.has(role)) throw new Error(`Unknown scan role: ${role}`);
  const P = (k) => ports[k] ?? 0;
  const conns = new Set();
  const servers = [];
  const graph = webappGraph(role, flag);
  if (role === "scan-apache") {
    servers.push(await listenHttp(host, P("http80"), apacheHandler, conns));
    servers.push(await listenHttp(host, P("http9999"), webappHandler(graph), conns));
  } else if (role === "scan-jetty") {
    servers.push(await listenHttp(host, P("http8080"), jettyHandler, conns));
    servers.push(await listenHttp(host, P("http9999"), webappHandler(graph), conns));
  } else if (role === "scan-web-a") {
    servers.push(await listenHttp(host, P("http80"), plainHandler("Apache/2.4.41 (Ubuntu)"), conns));
    servers.push(await listenHttp(host, P("http9999"), webappHandler(graph), conns));
  } else {
    servers.push(await listenHttp(host, P("http80"), plainHandler("nginx/1.21.0"), conns));
    servers.push(await listenHttp(host, P("http9999"), webappHandler(graph), conns));
  }
  let sshChild = null;
  let sshBound = null;
  if (role === "scan-apache" && ssh?.user && ssh?.password) {
    const script = new URL("./vuln-ssh-server.py", import.meta.url).pathname;
    const sshPort = ssh.port ?? 0;
    // The password travels via environment (same-UID-only visibility),
    // never argv (world-visible in ps output).
    sshChild = spawn("python3", [script, host, String(sshPort), ssh.user], {
      stdio: ["ignore", "pipe", "ignore"],
      env: { ...process.env, AXIOM_SSH_PW: String(ssh.password) },
    });
    // The sidecar prints READY <port> once bound (ephemeral ports included).
    sshBound = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("SSH sidecar failed to start")), 15000);
      let buf = "";
      sshChild.stdout.on("data", (d) => {
        buf += d.toString("utf8");
        const m = /READY (\d+)/.exec(buf);
        if (m) { clearTimeout(timer); resolve(parseInt(m[1], 10)); }
      });
      sshChild.on("exit", (code) => { clearTimeout(timer); reject(new Error(`SSH sidecar exited ${code}`)); });
    }).catch(async (e) => {
      try { sshChild.kill("SIGKILL"); } catch {}
      sshChild = null;
      throw e;
    });
  }
  const bound = {};
  const keys = role === "scan-apache" ? ["http80", "http9999"]
    : role === "scan-jetty" ? ["http8080", "http9999"]
    : ["http80", "http9999"];
  servers.forEach((s, i) => { bound[keys[i]] = s.address().port; });
  return {
    role,
    ports: bound,
    sshPort: sshBound,
    close: async () => {
      if (sshChild) try { sshChild.kill("SIGKILL"); } catch {}
      for (const c of conns) { try { c.destroy(); } catch {} }
      conns.clear();
      for (const s of servers) await new Promise((r) => s.close(r)).catch(() => {});
    },
  };
}

// Standalone entrypoint (used by the Docker image).
//   TARGET_ROLE=...  TARGET_HOST=0.0.0.0  FLAG_723=...  SCAN_SSH_USER=...
//   SCAN_SSH_PASSWORD=...  (fixed service ports in containers)
const invokedAsMain = (() => {
  try { return process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]; } catch { return false; }
})();
if (invokedAsMain) {
  const role = process.env.TARGET_ROLE || "";
  if (!SCAN_ROLES.has(role)) {
    console.error("TARGET_ROLE must be scan-apache|scan-jetty|scan-web-a|scan-web-b");
    process.exit(1);
  }
  const fixed = process.env.TARGET_FIXED_PORTS === "1";
  const fp = (p) => (fixed ? p : 0);
  startScanRole(role, {
    host: process.env.TARGET_HOST || "0.0.0.0",
    ports: role === "scan-apache"
      ? { http80: fp(80), http9999: fp(9999) }
      : role === "scan-jetty"
        ? { http8080: fp(8080), http9999: fp(9999) }
        : { http80: fp(80), http9999: fp(9999) },
    flag: process.env.FLAG_723 || "",
    ssh: role === "scan-apache" && process.env.SCAN_SSH_USER && process.env.SCAN_SSH_PASSWORD
      ? { user: process.env.SCAN_SSH_USER, password: process.env.SCAN_SSH_PASSWORD, port: fixed ? 22 : 0 }
      : null,
  })
    .then(() => console.log(`axiom-lab-scan target role=${role} listening`))
    .catch((e) => { console.error("scan target failed to start", e?.message || e); process.exit(1); });
}
