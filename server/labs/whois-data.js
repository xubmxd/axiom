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
