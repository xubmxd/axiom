# Lumen — Self-Hosted Learning Platform

A calm, premium, self-hosted learning workspace for your downloaded video & reading courses.
Dark-first original design, custom video player, platform-native HTML reader, real learning
statistics (genuine watch time + active reading time), contribution graph with adaptive
intensity, streaks, invite-only multi-user accounts, and an admin console.

## Quick start (local, SQLite — zero config)

```bash
npm install
npm start                      # http://localhost:3100
npm run bootstrap:admin -- <username> <email> <password> [display-name]
```

Put courses in `courses/` (see `courses/README.md`), sign in as admin → **Rescan courses**.

## Docker (production, PostgreSQL)

```bash
cp .env.example .env   # set SESSION_SECRET, APP_URL
docker compose up -d --build
docker compose exec app npm run bootstrap:admin -- admin you@home.local <password>
```

Volumes: `./courses` (read-only course files), `appdata` (SQLite fallback — unused with
Postgres), `pgdata` (database). Course files survive container recreation.

## Configuration (env)

| Var | Default | Purpose |
|---|---|---|
| `PORT` / `APP_URL` | 3100 | listen port / public URL (invite links) |
| `COURSES_ROOT` / `DATA_DIR` | ./courses ./data | course files / sqlite file |
| `DATABASE_URL` | — (SQLite) | `postgres://…` enables PostgreSQL |
| `SESSION_SECRET` | — | **required in prod**, httpOnly cookie sessions |
| `VIDEO_COMPLETION_THRESHOLD` | 0.9 | auto-complete fraction |
| `READING_COMPLETION_THRESHOLD` | 0.9 | scroll fraction auto-complete |
| `READING_INACTIVITY_TIMEOUT` | 60 | seconds without interaction → pause timer |
| `STREAK_MINUTES` | 15 | meaningful-day threshold |

## Architecture

```
courses/ (source of truth) → scanner (watcher + rescan, idempotent, stable path_key identities)
  → SQLite/Postgres index → Express (auth · authz · progress · sessions · stats authority)
  → server-rendered UI + vanilla JS (video.js genuine-watch-time · reader.js active-time)
```

- Progress derives from per-item state; rescans upsert by `(course_id, path_key)` with
  `is_active` soft-delete — new lessons recalculate %, never reset progress.
- Recursive `content_groups` (unlimited depth, display-only Module/Submodule/Section
  labels); flat courses get no fake groups. Files are classified: video → lessons,
  HTML → reading pages, txt/pdf/srt/etc. → resources (same-basename companions attach
  to their lesson, subtitles become `<track>`s). Moved files are re-linked by
  basename+size so progress follows renames.
- Imported HTML is **untrusted**: server-side sanitizer allowlists tags, strips scripts /
  handlers / dangerous URLs, rewrites images to authed media endpoints; no iframe, no
  imported JS on the app origin. Range-request video streaming, path-traversal guards,
  per-resource ownership checks, scrypt passwords, rate-limited login, single-use expiring
  invites, structured JSON logs, UTC storage with user-timezone day attribution.

## Tests

`npm test` — scanner ordering, sanitizer/XSS, traversal guard, timezone day split,
adaptive bands. Manually exercised: login (username+email), invites, rescan progress
preservation, resume, completion, heartbeat aggregation, admin controls.
