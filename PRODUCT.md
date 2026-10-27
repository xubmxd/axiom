# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Primarily a private cohort of invited learners being trained by the operator: they sign in through single-use admin invites, work through the operator's video and reading courses, and complete CarnoSec labs, sometimes from a Kali machine over the student WireGuard VPN. The operator also uses the platform themselves as an admin learner.

## Product Purpose

CarnoSec is a self-hosted learning workspace that turns the operator's own downloaded course libraries into tracked learning: honest watch time and active reading time, per-lesson progress, streaks, and a contribution graph, plus an attached Cyber Range of isolated hands-on labs with objective/flag validation. Success means learners actually finish courses and labs, and every number the platform reports about that is genuine.

## Positioning

The curriculum is plain folders on the operator's disk, scanned into a private instance that runs entirely on the operator's own hardware — no cloud service, no open signup — with optional isolated cyber labs wired into the same progress system. A neighboring cloud LMS cannot truthfully copy that: it would require the customer's files to live on someone else's servers and an internet-only operating model.

## Operating Context

- The operator curates course folders on disk (`courses/`, plus extra course libraries added from the admin panel) and rescans; the scanner is the ingestion path, not an upload UI.
- Accounts exist only via single-use, expiring admin invite links; roles are `admin` and `user`.
- Learners study in a browser over home/LAN networks; lab targets run on isolated Docker networks (`LAB_PROVIDER=docker`, `local` for dev) or are reached through optional WireGuard packs so Kali can connect to lab subnets.
- Deployment is local SQLite for zero-config runs or Docker Compose + PostgreSQL in production; environment variables configure ports, paths, thresholds, and VPN endpoints.
- The repository folder is named `ctf-platform`, while the package, UI, and GitHub repository (`xubmxd/carnosec`) use the name CarnoSec.

## Capabilities and Constraints

- Course scanning from folders: video → lessons, HTML → reading pages, resources and subtitles attach to lessons; recursive content groups; rescans preserve learner progress by stable path identity and re-link moved files.
- Custom video player with genuine-watch-time tracking; platform-native HTML reader with active reading time, scroll-based completion, and an inactivity timeout; server-side sanitizer on all imported HTML.
- Learning statistics authority: per-day activity, adaptive contribution-graph bands, streaks with a meaningful-day minute threshold, UTC storage with per-user timezone day attribution.
- Invite-only multi-user accounts, admin console (users, invites, scan state, course libraries, lab instances, VPN revocations).
- Cyber Range: declarative `lab.json` definitions (`labs/`) placed into training paths/modules; lab workspace with instructions, graded hints, in-browser terminal and scanner tabs, notes, and objective submission with validation; new labs require only a definition file plus restart.
- Optional student VPN (WireGuard) for reaching lab networks from Kali.
- Constraints that must be preserved: self-hosted only (no cloud SaaS assumptions), invite-only access (no open registration), LAN/VPN-capable operation.
- Open decision: the product name is not confirmed as a binding commitment — README/package/GitHub say "CarnoSec", the folder says "ctf-platform".

## Brand Commitments

None confirmed as binding. "CarnoSec" is the current working name (README, `package.json`, GitHub `xubmxd/carnosec`) with a logo asset at `carno-sec.png`, but the user did not pin the name as a commitment; treat renaming as an open question rather than an invariant.

## Evidence on Hand

- Real course content: `courses/video/` and `courses/reading/`.
- Seventeen complete lab definitions with targets, objectives, hints, and UI copy: `labs/module-06/` (OSINT/recon: whois, Google hacking, Netcraft, DNS, port scanning, nmap, SMB, SMTP, SNMP) and `labs/module-07/` (vulnerability scanning with Nessus), plus Docker build files in `lab-images/`.
- Logo asset: `carno-sec.png`.
- `README.md` documenting quick start, Docker deploy, configuration, and architecture.
- Automated tests: `npm test` (scanner ordering, sanitizer/XSS, traversal guard, timezone day split, adaptive bands).
- Absences future work must not fabricate: no DESIGN.md, no testimonials, customers, press, benchmarks, or pricing.

## Product Principles

1. Progress data is honest — statistics derive from genuine watch and reading activity, never padded or estimated for show.
2. The operator's infrastructure is the product — every new capability must work self-hosted, on the operator's own hardware, over LAN/VPN.
3. Access stays closed — accounts come only through single-use admin invites; no open registration.
4. The learning library leads; the Cyber Range is an attached feature, not the identity — surfaces read as one coherent learning workspace.
5. Course files on disk are the source of truth — rescans and renames must never destroy learner progress.
