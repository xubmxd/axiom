// Canonical WHOIS dataset for the Module 6 / 6.2.1 / VM #1 lab.
//
// This is independently recreated infrastructure: realistic-looking WHOIS
// output for the fictional domain megacorpone.com. The discovery path is:
//
//   whois megacorpone.com -h <TARGET-IP>
//     → Name Server entries (third: ns3.megacorpone.com)
//     → Registrar WHOIS Server entry (whois.gandi.net)
//
// The same builder is used by every orchestrator provider (docker target,
// local-process fallback) so the observable challenge is identical no
// matter which provider provisioned the instance.
//
// VM #2 (same exercise, example.net) lives below. Its record is
// built per instance with a runtime flag embedded in the DNS section — VM #1
// output is byte-identical to before.
export const LAB_DOMAIN = "megacorpone.com";
export const THIRD_NAMESERVER = "ns3.megacorpone.com";
export const REGISTRAR_WHOIS = "whois.gandi.net";

export function buildWhoisResponse(query) {
  const q = String(query || "").trim().toLowerCase();
  if (!q || q === LAB_DOMAIN || q === `domain ${LAB_DOMAIN}`) return domainResponse();
  if (q === "ns1.megacorpone.com" || q === "ns2.megacorpone.com" || q === "ns3.megacorpone.com") return nameserverResponse(q);
  return notFoundResponse(String(query || "").trim());
}

function domainResponse() {
  return [
    `Domain Name: ${LAB_DOMAIN.toUpperCase()}`,
    `Registry Domain ID: 2817742_DOMAIN_COM-VRSN`,
    `Registrar WHOIS Server: ${REGISTRAR_WHOIS}`,
    `Registrar URL: http://www.gandi.net`,
    `Updated Date: 2024-11-02T09:14:22Z`,
    `Creation Date: 1998-03-15T05:00:00Z`,
    `Registry Expiry Date: 2027-03-14T04:00:00Z`,
    `Registrar: Gandi SAS`,
    `Registrar IANA ID: 81`,
    `Registrar Abuse Contact Email: abuse@support.gandi.net`,
    `Registrar Abuse Contact Phone: +33.170377661`,
    `Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited`,
    `Name Server: NS1.MEGACORPONE.COM`,
    `Name Server: NS2.MEGACORPONE.COM`,
    `Name Server: NS3.MEGACORPONE.COM`,
    `DNSSEC: unsigned`,
    ``,
    `>>> Last update of whois database: 2026-09-20T12:00:00Z <<<`,
    ``,
    `For more information on Whois status codes, please visit https://icann.org/epp`,
    ``,
    `NOTICE: The expiration date displayed in this record is the date the`,
    `registrar's sponsorship of the domain name registration in the registry is`,
    `currently set to expire. This date does not necessarily reflect the expiration`,
    `date of the domain name registrant's agreement with the sponsoring`,
    `registrar.`,
  ].join("\r\n") + "\r\n";
}

function nameserverResponse(ns) {
  const host = ns.toUpperCase();
  return [
    `Server Name: ${host}`,
    `IP Address: 93.184.216.${ns.startsWith("ns3") ? "34" : ns.startsWith("ns2") ? "33" : "32"}`,
    `Registrar: Gandi SAS`,
    `Registrar WHOIS Server: ${REGISTRAR_WHOIS}`,
    `Registrar URL: http://www.gandi.net`,
    `Updated Date: 2024-11-02T09:14:22Z`,
    `Creation Date: 1998-03-15T05:00:00Z`,
    ``,
    `>>> Last update of whois database: 2026-09-20T12:00:00Z <<<`,
  ].join("\r\n") + "\r\n";
}

function notFoundResponse(q) {
  const safe = q.slice(0, 128).toUpperCase() || "UNKNOWN";
  return [
    `No match for domain "${safe}".`,
    `>>> Last update of whois database: 2026-09-20T12:00:00Z <<<`,
  ].join("\r\n") + "\r\n";
}

// Minimal zone facts backing the scoped `dig`/`nslookup` helpers in the
// integrated terminal. These mirror the WHOIS dataset; they are not a fake
// of the WHOIS service itself (whois always goes over real TCP/43).
export const ZONE = {
  domain: LAB_DOMAIN,
  ns: ["ns1.megacorpone.com", "ns2.megacorpone.com", "ns3.megacorpone.com"],
  registrarWhois: REGISTRAR_WHOIS,
};

// ---------- VM #2: example.net (same 6.2.1 exercise) ----------
// Independently recreated record for the lab domain example.net.
// The discovery path is:
//
//   whois example.net -h <TARGET-IP>
//     → DNS section of the response
//     → flag embedded as a DNS TXT verification token
//
// The flag is a per-instance runtime value (AXIOM{…}) injected at
// provisioning time — never stored in the lab definition, never sent to the
// browser except inside the live WHOIS response itself.
export const VM2_SLUG = "m6-6-2-1-whois-vm2";
export const VM1_SLUG = "m6-6-2-1-whois-vm1";
export const VM2_DOMAIN = "example.net";
export const VM2_REGISTRAR_WHOIS = "whois.tucows.com";

export const VM2_ZONE = {
  domain: VM2_DOMAIN,
  ns: ["ns1.example.net", "ns2.example.net"],
  registrarWhois: VM2_REGISTRAR_WHOIS,
};

// Lab → domain mapping used by the orchestrator, routes, and terminal so
// each lab queries its own domain. Unknown labs fall back to VM #1's domain
// (existing behavior is unchanged).
export function labDomain(labOrSlug) {
  const slug = typeof labOrSlug === "string" ? labOrSlug : labOrSlug?.slug || "";
  return slug === VM2_SLUG || slug === VM3_SLUG ? VM2_DOMAIN : LAB_DOMAIN;
}

export function labZone(labOrSlug) {
  const slug = typeof labOrSlug === "string" ? labOrSlug : labOrSlug?.slug || "";
  return slug === VM2_SLUG || slug === VM3_SLUG ? VM2_ZONE : ZONE;
}

export function buildVm2WhoisResponse(query, flag) {
  const q = String(query || "").trim().toLowerCase();
  if (!q || q === VM2_DOMAIN || q === `domain ${VM2_DOMAIN}`) return vm2DomainResponse(flag);
  if (q === "ns1.example.net" || q === "ns2.example.net") return vm2NameserverResponse(q);
  return vm2NotFoundResponse(String(query || "").trim());
}

function vm2DomainResponse(flag) {
  const token = String(flag || "AXIOM{unprovisioned}").slice(0, 128);
  return [
    `Domain Name: ${VM2_DOMAIN.toUpperCase()}`,
    `Registry Domain ID: 3120458_DOMAIN_COM-VRSN`,
    `Registrar WHOIS Server: ${VM2_REGISTRAR_WHOIS}`,
    `Registrar URL: http://www.tucows.com`,
    `Updated Date: 2025-08-19T14:22:10Z`,
    `Creation Date: 2006-06-08T18:00:00Z`,
    `Registry Expiry Date: 2028-06-08T18:00:00Z`,
    `Registrar: Tucows Domains Inc.`,
    `Registrar IANA ID: 69`,
    `Registrar Abuse Contact Email: domainabuse@tucows.com`,
    `Registrar Abuse Contact Phone: +1.4165350121`,
    `Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited`,
    `Name Server: NS1.EXAMPLE.NET`,
    `Name Server: NS2.EXAMPLE.NET`,
    `DNSSEC: unsigned`,
    `DNS Status: active`,
    `DNS Primary: NS1.EXAMPLE.NET`,
    `DNS Serial: 2026081901`,
    `DNS TXT: axiom-verification=${token}`,
    ``,
    `>>> Last update of whois database: 2026-09-20T12:00:00Z <<<`,
    ``,
    `For more information on Whois status codes, please visit https://icann.org/epp`,
  ].join("\r\n") + "\r\n";
}

function vm2NameserverResponse(ns) {
  const host = ns.toUpperCase();
  return [
    `Server Name: ${host}`,
    `IP Address: 198.51.100.${ns.startsWith("ns2") ? "53" : "52"}`,
    `Registrar: Tucows Domains Inc.`,
    `Registrar WHOIS Server: ${VM2_REGISTRAR_WHOIS}`,
    `Registrar URL: http://www.tucows.com`,
    `Updated Date: 2025-08-19T14:22:10Z`,
    `Creation Date: 2006-06-08T18:00:00Z`,
    ``,
    `>>> Last update of whois database: 2026-09-20T12:00:00Z <<<`,
  ].join("\r\n") + "\r\n";
}

function vm2NotFoundResponse(q) {
  const safe = q.slice(0, 128).toUpperCase() || "UNKNOWN";
  return [
    `No match for domain "${safe}".`,
    `>>> Last update of whois database: 2026-09-20T12:00:00Z <<<`,
  ].join("\r\n") + "\r\n";
}

// ---------- VM #3: example.net Tech Email (same 6.2.1 exercise) ----------
// Independently recreated record for the same lab domain. The discovery path is:
//
//   whois example.net -h <TARGET-IP>
//     → inspect the returned record
//     → Tech Email address
//
// Unlike VM #2 there is no per-instance secret here: the answer is a
// controlled static value validated by the existing hashed-objective
// mechanism (case-insensitive, like other email/hostname answers). It is
// never stored in the lab definition and never sent to the browser — only
// the live WHOIS response carries it.
export const VM3_SLUG = "m6-6-2-1-whois-vm3";
export const TECH_EMAIL = "tech@example.net";

export function buildVm3WhoisResponse(query) {
  const q = String(query || "").trim().toLowerCase();
  if (!q || q === VM2_DOMAIN || q === `domain ${VM2_DOMAIN}`) return vm3DomainResponse();
  if (q === "ns1.example.net" || q === "ns2.example.net") return vm2NameserverResponse(q);
  return vm2NotFoundResponse(String(query || "").trim());
}

function vm3DomainResponse() {
  return [
    `Domain Name: ${VM2_DOMAIN.toUpperCase()}`,
    `Registry Domain ID: 3120458_DOMAIN_COM-VRSN`,
    `Registrar WHOIS Server: ${VM2_REGISTRAR_WHOIS}`,
    `Registrar URL: http://www.tucows.com`,
    `Updated Date: 2025-08-19T14:22:10Z`,
    `Creation Date: 2006-06-08T18:00:00Z`,
    `Registry Expiry Date: 2028-06-08T18:00:00Z`,
    `Registrar: Tucows Domains Inc.`,
    `Registrar IANA ID: 69`,
    `Registrar Abuse Contact Email: domainabuse@tucows.com`,
    `Registrar Abuse Contact Phone: +1.4165350121`,
    `Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited`,
    `Name Server: NS1.EXAMPLE.NET`,
    `Name Server: NS2.EXAMPLE.NET`,
    `DNSSEC: unsigned`,
    `DNS Status: active`,
    `DNS Primary: NS1.EXAMPLE.NET`,
    `DNS Serial: 2026081901`,
    `Tech Name: Example Operations`,
    `Tech Email: ${TECH_EMAIL}`,
    `Tech Phone: +1.2125550148`,
    ``,
    `>>> Last update of whois database: 2026-09-20T12:00:00Z <<<`,
    ``,
    `For more information on Whois status codes, please visit https://icann.org/epp`,
  ].join("\r\n") + "\r\n";
}
