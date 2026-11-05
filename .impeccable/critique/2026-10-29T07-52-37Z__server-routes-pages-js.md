---
target: primary learner surface + shared shell (Workspace, Library, Course, lesson, reader, Cyber Range, Lab, Profile, Settings, Admin)
total_score: 23
max_score: 40
na_heuristics: 
p0_count: 1
p1_count: 3
target_identity: "file:/home/xubm/Desktop/personal/projects/ctf-platform/server/routes-pages.js"
target_fingerprint: "sha256:a1fc47aa011b10aa8b718dd89e3fecfcbb036ce7eef178ee7e238388125cbd7e"
target_path: /home/xubm/Desktop/personal/projects/ctf-platform/server/routes-pages.js
timestamp: 2026-10-29T07-52-37Z
slug: server-routes-pages-js
---
# CarnoSec — Design Critique

**Target:** primary learner surface + shared shell (Workspace `/`, Library, Course detail, lesson player, reader, Cyber Range index, Lab workspace, Profile, Settings, Admin). No single page was named, so the review covers the product's main task surfaces.

**Method:** degraded single-context. The sub-agent tool is present but blocked by a session depth limit, so Assessment A (design review) and Assessment B (detector + browser evidence) ran sequentially in one context. A was completed before the full detector sweep; one preflight detector result for the Workspace was visible during browser setup before A concluded.

## Design Health Score

| # | Heuristic | Score | Key Issue |
|---|-----------|-------|-----------|
| 1 | Visibility of System Status | 2 | Settings saves are silent and dead; the same reading page reports 0% and 7%; "systems online" is static |
| 2 | Match System / Real World | 2 | Filesystem paths, provider/reset metadata and distributor tags reach learners |
| 3 | User Control and Freedom | 3 | Back, collapse, cancel, sign-out confirm exist; Escape does not close the account menu; lab reset has no confirm |
| 4 | Consistency and Standards | 2 | "axiom" footer, 0%/7%, two search fields, uppercase module names only in the player, ISO dates only in admin |
| 5 | Error Prevention | 2 | Settings submits credentials in a GET and discards edits; a complete course still offers bulk marking |
| 6 | Recognition Rather Than Recall | 3 | Strong keyboard cheat sheet, page TOC, copyable commands; collapsed rail is tooltip-only |
| 7 | Flexibility and Efficiency | 3 | Bulk select, expand all, lesson filter, focus mode, player shortcuts; no global navigation shortcut |
| 8 | Aesthetic and Minimalist Design | 2 | Coherent system, but many 60%-empty screens, nested cards on OSCP, dead bulk bar, duplicate labels |
| 9 | Error Recovery | 2 | Good inline correct/incorrect and toasts; settings failures are invisible and lose data |
| 10 | Help and Documentation | 2 | Excellent lab context; no explanation of the streak threshold, no global help, "contact your admin" without a route |
| **Total** | | **23/40** | **Acceptable** |

Honest read: 23/40. The craft in the player and lab workspace is above this number; the broken settings flow, contradictory progress numbers and mobile task order pull it down.

## Design Specificity Verdict

**LLM assessment — partly authored, partly category-default.** The Lab workspace and the lesson player are unmistakably this product: target status, connection details gated until start, copyable commands, per-objective answer validation, notes that promise persistence, and a keyboard legend under the video (`space/k play · ←/→ 5s · f fullscreen · m mute · p PiP`). The surrounding LMS shell is not: a left rail, four stat cards, a contribution graph, a card list of courses and a full-width marketing hero on the Cyber Range index is the recognizable "dark cyber dashboard" template. Near-black plus emerald plus mono micro-labels is the current default of that category, not a CarnoSec-specific world.

The product's real differentiators are under-expressed. "Every number is genuine" has no visual language: no provenance, no distinction between watched and claimed time, no verified mark. The folder-scan identity is reduced to a raw path (`source: Default library/video/TCM - Python 101 for Hackers`) instead of a provenance signal. "Learn > practice > progress" is a decorative tagline under the logo, not the navigational spine connecting Library and Cyber Range. And the cartoon course art plus the red-eyed logo fight the terminal aesthetic the CSS explicitly commits to.

**Deterministic scan.** 12 scans (9 desktop, 3 mobile) → 80 failures, 19 advisories before de-duplication. Recurring rules: `undersized-ui-text` (profile calendar: 24 instances at 9.28px; labels at 10.24px on 6 surfaces), `wide-tracking` (12/12, on the sidebar footer), `nested-cards` (22; 21 are the same OSCP lab-row pattern), `skipped-heading` (Library, Course, Settings: h1 → h3), `low-contrast` placeholders at 4.1:1 (Library search, admin inputs), and one real `script-error` on Settings (`ReferenceError: saveJSON is not defined`). The detector caught the settings breakage, the calendar type floor and the heading jumps; the review caught the 0%/7% contradiction, the mobile task-order inversion, the stale brand and the Google Fonts dependency, none of which the detector can see. False positives: `wide-tracking` on the decorative `.appnav-foot`; `numbered-section-labels` on the intentional 01/02/03 "How it works" steps; `em-dash-overuse` (copy style, advisory). `nested-cards` is a true pattern but the per-row count overstates it.

**Visual overlays.** Injection succeeded on the Workspace in the disposable headless browser: the console reported `6 anti-patterns found` and 6 highlights rendered (screenshot: `/tmp/opencode/crit/shots/overlay-home.png`). There is no `[Human]` tab to click because the instance is a headless copy.

## Overall Impression

This is a credible, well-engineered learning product with two genuinely designed moments — the player and the lab — wrapped in a shell that is handsome but generic, and undermined by a few broken or contradictory details at the exact points where trust is built. The single biggest opportunity: make "honest progress" visible as a design language, not just a database rule.

## What's Working

1. **The lesson player.** Custom controls, a visible keyboard legend, a course tree with per-module rings, focus mode, resume that saves automatically, and a next-lesson CTA. It respects a learner who is going to spend hours here.
2. **The lab workspace's state model.** "Lab status: Stopped / Not running" paired with a prominent Start, connection details that say "Start the lab to get connection details", notes that say "Private to you. Saved with this lab", and inline `✓ Correct` / `✗ Incorrect — try again` feedback. Self-healing status reconciliation when Docker is slow is unusually thoughtful.
3. **The visual system's restraint.** One accent, border-defined depth, tabular numerals, consistent radii, no gradients or glow, and empty states written in plain language. The `data-terminal` world is coherent where it is applied.

## Priority Issues

### [P0] Settings cannot save — and puts credentials in the URL
- **What:** `/settings` throws `ReferenceError: saveJSON is not defined`. The inline script that assigns `onsubmit` runs before deferred `app.js` defines `window.saveJSON`, so `onsubmit` stays `null`. Submitting "Save profile" performs a GET to `/settings?display_name=…&email=…&timezone=…`, reloads, and discards the edit. Password and preferences are equally dead.
- **Why it matters:** a learner cannot change their password or preferences, and an admin cannot fix their own profile. The email address lands in browser history and server logs. The page looks finished, so the failure is silent.
- **Fix:** attach the handlers after `app.js` loads (move the inline block below the deferred script or wrap in `DOMContentLoaded`), give each form `method="post"` + `preventDefault`, surface a persistent "Saved" status, and never allow a fallback GET that carries account fields.
- **Suggested command:** `/impeccable harden`

### [P1] Mobile inverts the task order on both core flows
- **What:** at 390px the lab page runs instructions → terminal → "Lab Status: Stopped" → "Start Lab" → answer fields. The primary action sits ~1000px below the tool it activates, and a learner can type into a terminal for a lab that is not running. On the reading page the course panel and its 12-item "On this page" TOC occupy the first viewport; the article and its progress bar begin below 844px.
- **Why it matters:** mobile learners start in the wrong place and cannot see state while acting. "Continue reading" from the dashboard lands on navigation, not the text.
- **Fix:** on mobile, place a compact status + Start/Reset bar directly under the lab title (sticky), then objectives/answers, then the terminal as a bottom sheet that enables only when running. Collapse the reading TOC into a "Contents" disclosure and render the article first, restoring scroll position.
- **Suggested command:** `/impeccable adapt`

### [P1] Progress numbers contradict each other and the product's promise
- **What:** the Library card says "Offsec SOC 100 — 0%", the reader sidebar says "0% complete", the reader's top bar shows 7%, and the dashboard says "7% through this page". A completed lesson appears in "Continue learning" as `0:00 / 5:35 · 0%` with a "Revisit" button.
- **Why it matters:** honest progress is the product's first principle. A learner seeing two numbers for one page reads it as broken accounting, and a completed item at 0% erodes the trust the rest of the stats earn.
- **Fix:** separate item partial progress from course completion in language and visual form — e.g. "1 of 39 items complete" plus "7% of this page read" — and never render a 0% bar for a completed item. If a single course percentage is required, define it as a weighted blend and say so.
- **Suggested command:** `/impeccable clarify`

### [P1] The accessibility floor is below the line
- **What:** the focus ring is `rgba(62,207,142,.30)` (≈1.3:1 against the surface) on every focusable element; heatmap cells are focusable but have no accessible name and their tooltip is `aria-hidden`; profile calendar day numbers are 9.28px; eyebrows are 10.24px; placeholders are 4.1:1; Library/Course/Settings jump from `h1` to `h3`; tab order traverses the whole sidebar before the topbar search; Escape does not close the account menu.
- **Why it matters:** keyboard and low-vision learners cannot see where they are, cannot read the dates, and get nothing from tabbing across 364 activity cells.
- **Fix:** a solid focus ring at ≥3:1; `aria-label` on each heatmap cell with the full tooltip text (and a real table/grid role); raise the micro-type floor to 11px and calendar numbers to ≥12px; darken placeholders; insert `h2`s; give the account menu Escape handling.
- **Suggested command:** `/impeccable audit` (then `/impeccable typeset` for the floor)

### [P2] Trust signals drift from the product's own claims
- **What:** every page, including the login screen, ends with `axiom · v1.0 · self-hosted`; the sidebar repeats `carno-sec · self-hosted · v1.0`; "systems online" is a hard-coded green dot; `DM Sans` is requested but never used, while `Public Sans` and `Source Code Pro` are fetched from Google Fonts on every load.
- **Why it matters:** the platform sells honest, self-hosted operation. A stale brand and a status light that never changes read as theatre. On the LAN-only deployment the product describes, Google Fonts fail and the entire type identity falls back to system fonts — the one environment the product is built for.
- **Fix:** one brand string from a constant; wire the status dot to real lab/scanner health or remove it; self-host the two used families and drop DM Sans.
- **Suggested command:** `/impeccable harden`

## Persona Red Flags

**Sam (accessibility, keyboard-only, low vision).** Tabs into the sidebar before the search field. The focus ring is a 30%-alpha hairline, effectively invisible on the near-black surface. Tabbing the Activity graph lands on 364 unnamed cells; the tooltip is `aria-hidden`, so the only per-day data is visual. On Profile the calendar's day numbers render at 9.28px. On Settings, activating "Save profile" reloads the page and loses the edit with no error. The account menu stays open on Escape. Library and Course skip from `h1` to `h3`.

**Casey (mobile, one-handed, interrupted).** Opens a lab: the first screen is instructions, the second is a terminal, and "Start Lab" is below both — after scrolling past a target that is still stopped. Opens a reading page: the first viewport is a 12-link contents list; the article begins below the fold. Heatmap cells are 16.5px tap targets; the hamburger is 38×34 and the account chip 39×35. Module lesson counts (`4 lessons`) are `display:none` below 900px, so she cannot judge what a module contains before expanding it. The video volume slider is present and useless on a phone.

**Alex (power user).** Has keyboard shortcuts for the player and Ctrl K for search, bulk selection, expand/collapse and focus mode — then hits a Settings page where three separate Save buttons do nothing. No shortcut for next lesson, next page, or moving between Library and Cyber Range. The resume card's next-lesson label is truncated with the distributor tag (`3. What is Python [ @redbloc…`), making the sequence hard to scan. No command palette or recent-items list across courses.

## Minor Observations

- **Dead end empty state:** "In progress" says "Nothing in progress. Something new is waiting in the library." with no link, directly under a "View all →".
- **Library cards are 40% empty:** two full-width cards with a large blank lower half; the meta row (`0%` / `1 page`) floats far from the bar it describes.
- **Two search fields on Library:** topbar (`aria-label="Search courses, lessons, pages"`, placeholder "Search the library…") and toolbar (`placeholder="Search courses, lessons, pages…"`). Same intent, different names, no explanation.
- **OSCP page is three borders deep:** module card → exercise group → lab row, repeated 21 times. The detector counted 21 nested cards; the real issue is one pattern applied to every row.
- **Cyber Range index is a hero for a logged-in user with one path:** "Practical cybersecurity training environments." plus a three-step explainer above a single OSCP card and "1 available". The one useful action is below the fold.
- **Identity duplication:** `Course complete` banner plus "100% · 38/38" plus a "100% complete" seal; "reading course" plus a `reading` pill; "library · 2 courses" plus "Course library".
- **Completed course still offers bulk marking:** Select all / Mark as watched / Mark as unwatched / Clear, all disabled. Remove the bar when the course is complete.
- **Settings asks for an IANA timezone in a free-text field** while the rest of the product knows the device clock; offer a picker or a sensible default from `Intl`.
- **Admin table friction:** the library path breaks mid-word; "Recent activity" uses `2026-10-27` while every other surface uses "Oct 27, 2026"; "learned 11m 35s" has no scope (all users vs this user); "you" sits in a column with no header.
- **Lab "More" tab** exposes `PROVIDER –`, `RESETS 0`, `TYPE single-target` with no explanation; **Hints (0)** leads to an empty panel — hide or dim the tab.
- **Distributor tags in titles:** `[@redblock team]` dominates the player's h1 and truncates every sidebar row. `TITLE_STRIP` exists; configure it.
- **Reset has no confirmation** while a lab is running, though it rebuilds the environment.
- **The motivational quote** changes on every reload and can contradict the data ("Consistency beats intensity" beside a 0-day streak). It is charming; give it a stable choice or a tie to the streak.
- **Inline type patches:** the layout injects `<style>` with `!important` font-size overrides for eight selectors. That is a symptom of a type scale that is wrong at the source.
- **No `prefers-reduced-motion` handling** for the 150ms transitions and toast motion.

## Questions to Consider

1. If "every number is genuine" is the product's spine, what would a *proof of work* visual language look like — provenance on a course, a verified mark on a streak, a clear distinction between watched and claimed time?
2. The Lab workspace is the most specific thing here. Should the Workspace dashboard be organized around the next concrete lab/lesson rather than four aggregate stats?
3. On mobile, should the terminal become a persistent bottom sheet so status, instructions and answers stay in view instead of becoming a long linear document?
4. Course files are folders on disk. Should the Library surface that provenance (library, last scan, item count) as a first-class signal instead of hiding it in a raw path on the course page?
5. Is the rotating quote earning the most valuable line under the greeting, or should that line carry the next action?
