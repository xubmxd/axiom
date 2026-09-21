// Answer normalization + hashing for lab objective validation.
//
// Supported validation types:
//   exact                 — trimmed, case-sensitive (flags, tokens)
//   case-insensitive-exact— trimmed + lowercased (hostnames, domains)
//   flag                  — alias of exact (per-instance/runtime flags)
//
// Normalization: trim leading/trailing whitespace, collapse internal
// whitespace runs to a single space. Only correct/incorrect is ever
// revealed to the learner; expected values live server-side as hashes.
import crypto from "node:crypto";

export const VALIDATION_TYPES = new Set(["exact", "case-insensitive-exact", "flag"]);

export function normalizeAnswer(raw, validationType = "case-insensitive-exact") {
  let s = String(raw ?? "").trim().replace(/\s+/g, " ");
  if (validationType === "case-insensitive-exact") s = s.toLowerCase();
  return s;
}

export function hashAnswer(raw, validationType = "case-insensitive-exact") {
  return crypto.createHash("sha256").update(normalizeAnswer(raw, validationType), "utf8").digest("hex");
}

export function verifyAnswer(raw, expectedHash, validationType = "case-insensitive-exact") {
  if (!expectedHash) return false;
  const candidate = hashAnswer(raw, validationType);
  const a = Buffer.from(candidate, "hex");
  const b = Buffer.from(String(expectedHash), "hex");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

export function coerceValidationType(t) {
  return VALIDATION_TYPES.has(t) ? t : "case-insensitive-exact";
}
