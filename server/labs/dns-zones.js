// Canonical DNS dataset for the Module 6 / 6.3.1 DNS Enumeration lab.
//
// Independently recreated, fictional authoritative zones for
// megacorpone.com and megacorptwo.com. This data is the LAB TARGET
// itself (served by server/labs/dns-server.js on the isolated lab
// network) — it is not UI content and never ships to the browser except
// inside live DNS responses to the learner's own queries.
//
// Exercise-critical facts (must stay stable):
//   MX set on megacorpone.com  -> priorities {10, 20, 30}; second-best = 20
//   TXT count on megacorpone.com -> exactly 2 records
//   siem.megacorpone.com A     -> 51.222.169.215 (answer DATA, not the
//                                 target's own address — the lab DNS server
//                                 listens on an isolated RFC1918 address)
//   info.megacorptwo.com TXT   -> "greetings from the TXT record body"
//
// Record order in answers is deliberately NOT preference-sorted so the
// learner must interpret priority values rather than read the first row.
export const DNS_TTL = 3600;

export const DNS_ZONES = {
  "megacorpone.com": [
    { name: "@", type: "SOA", ttl: DNS_TTL, data: { mname: "ns1.megacorpone.com.", rname: "admin.megacorpone.com.", serial: 2026010101, refresh: 3600, retry: 600, expire: 86400, minimum: 300 } },
    { name: "@", type: "NS", ttl: DNS_TTL, data: "ns1.megacorpone.com." },
    { name: "@", type: "NS", ttl: DNS_TTL, data: "ns2.megacorpone.com." },
    { name: "@", type: "NS", ttl: DNS_TTL, data: "ns3.megacorpone.com." },
    // MX preference order in the zone file is intentionally unsorted.
    { name: "@", type: "MX", ttl: DNS_TTL, data: { preference: 30, exchange: "mail3.megacorpone.com." } },
    { name: "@", type: "MX", ttl: DNS_TTL, data: { preference: 10, exchange: "mail.megacorpone.com." } },
    { name: "@", type: "MX", ttl: DNS_TTL, data: { preference: 20, exchange: "mail2.megacorpone.com." } },
    { name: "@", type: "TXT", ttl: DNS_TTL, data: ["v=spf1 mx include:_spf.megacorpone.com ~all"] },
    { name: "@", type: "TXT", ttl: DNS_TTL, data: ["open-source-guard=1a2b3c4d5e"] },
    { name: "@", type: "A", ttl: DNS_TTL, data: "192.0.2.10" },
    { name: "ns1", type: "A", ttl: DNS_TTL, data: "192.0.2.53" },
    { name: "ns2", type: "A", ttl: DNS_TTL, data: "192.0.2.54" },
    { name: "ns3", type: "A", ttl: DNS_TTL, data: "192.0.2.55" },
    { name: "www", type: "A", ttl: DNS_TTL, data: "192.0.2.80" },
    { name: "mail", type: "A", ttl: DNS_TTL, data: "192.0.2.25" },
    { name: "mail2", type: "A", ttl: DNS_TTL, data: "192.0.2.26" },
    { name: "mail3", type: "A", ttl: DNS_TTL, data: "192.0.2.27" },
    { name: "siem", type: "A", ttl: DNS_TTL, data: "51.222.169.215" },
    { name: "support", type: "A", ttl: DNS_TTL, data: "192.0.2.81" },
    { name: "vpn", type: "A", ttl: DNS_TTL, data: "192.0.2.82" },
  ],
  "megacorptwo.com": [
    { name: "@", type: "SOA", ttl: DNS_TTL, data: { mname: "ns1.megacorptwo.com.", rname: "admin.megacorptwo.com.", serial: 2026010101, refresh: 3600, retry: 600, expire: 86400, minimum: 300 } },
    { name: "@", type: "NS", ttl: DNS_TTL, data: "ns1.megacorptwo.com." },
    { name: "@", type: "A", ttl: DNS_TTL, data: "192.0.2.100" },
    { name: "ns1", type: "A", ttl: DNS_TTL, data: "192.0.2.153" },
    { name: "www", type: "A", ttl: DNS_TTL, data: "192.0.2.101" },
    { name: "info", type: "A", ttl: DNS_TTL, data: "192.0.2.102" },
    { name: "info", type: "TXT", ttl: DNS_TTL, data: ["greetings from the TXT record body"] },
  ],
};

// Lab slug for the 6.3.1 DNS Enumeration exercise (shared by the
// orchestrator's terminal routing and tests).
export const DNS_SLUG = "m6-6-3-1-dns-enumeration";

// Brute-force wordlist backing the lab terminal's dnsenum-style
// enumeration. Real A queries are issued for each candidate; only names
// present in the zones above can ever hit.
export const DNS_BRUTE_WORDLIST = [
  "www", "mail", "mail2", "mail3", "siem", "support", "vpn",
  "ns1", "ns2", "ns3", "info", "ftp", "dev", "test", "blog",
  "shop", "api", "db", "admin", "intranet", "remote", "portal",
  "webmail", "mx", "dns", "secure", "vpn2", "backup",
];
