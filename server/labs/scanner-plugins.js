// Reusable Axiom vulnerability-scanner layer: plugin model, scan
// templates, and global scanner configuration.
//
// One source of truth for everything the scanner console renders:
// template categories (7.2.2 navigates them), the template list, and the
// advanced settings (7.2.2 reads the concurrent-web-users value from the
// live configuration, not from a static page).
//
// Severity choices below are implementation decisions — the supplied
// extract does not establish severities, and they are documented as such.
export const TEMPLATE_CATEGORIES = ["DISCOVERY", "COMPLIANCE", "VULNERABILITIES"];

export const SCAN_TEMPLATES = [
  { id: "basic", name: "Basic Network Scan", category: "VULNERABILITIES", description: "Full-system vulnerability scan suitable for any host." },
  { id: "discovery", name: "Discovery Scan", category: "DISCOVERY", description: "Host discovery and open-port enumeration without vulnerability checks." },
];

export const ADVANCED_SETTINGS = {
  concurrentWebUsers: 1024,
  maxHostsPerScan: 1024,
  scanTimeoutSeconds: 3600,
};

// Plugin catalog: the smallest useful reusable model. Detection functions
// live in the engine; metadata lives here. patch_pub_date bindings follow
// the supplied extract (the January 26, 2021 date is source-backed; its
// attachment to the Apache finding is an implementation choice documented
// in the fidelity report, since the extract does not bind it explicitly).
export const PLUGINS = {
  "ax-apache-traversal": {
    id: "ax-apache-traversal",
    name: "Apache 2.4.49 < 2.4.51 Path Traversal Vulnerability",
    family: "Web Servers",
    severity: "High",
    description: "The remote Apache server is affected by a path traversal vulnerability allowing unauthenticated file access outside the document root.",
    evidence: "Traversal probe returned 200 with passwd marker",
    remediation: "Upgrade to Apache 2.4.51 or later.",
    exploitCodeMaturity: "functional",
    patchPubDate: "January 26,2021",
  },
  "ax-http-multiple": {
    id: "ax-http-multiple",
    name: "HTTP (Multiple Issues)",
    family: "Web Servers",
    severity: "Medium",
    description: "The remote HTTP server discloses its type and version and groups informational HTTP findings.",
    evidence: "Server header version identification",
    remediation: "Harden HTTP response headers and review grouped findings.",
    exploitCodeMaturity: "unproven",
    patchPubDate: "January 26,2021",
  },
  "ax-curl-usn": {
    id: "ax-curl-usn",
    name: "Ubuntu Linux: curl Security Update (USN)",
    family: "Patch Report",
    severity: "Medium",
    description: "An installed curl build is affected by a Ubuntu Security Notice for this release.",
    evidence: "Package inventory match over SSH",
    remediation: "Apply the referenced Ubuntu Security Notice.",
  },
  "ax-ssh-os-ident": {
    id: "ax-ssh-os-ident",
    name: "OS Identification and Installed Software Enumeration over SSH v2 (Using New SSH Library)",
    family: "General",
    severity: "Info",
    description: "Authenticated SSH enumeration identified the remote operating system and installed software.",
    evidence: "uname -a over authenticated SSH",
    remediation: "No action required (informational).",
  },
};

export function matchPlugins(filter) {
  const q = String(filter || "").trim().toLowerCase();
  const all = Object.values(PLUGINS);
  if (!q) return all;
  return all.filter((p) =>
    p.name.toLowerCase().includes(q) ||
    p.family.toLowerCase().includes(q) ||
    p.id.toLowerCase().includes(q)
  );
}
