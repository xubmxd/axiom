// Dual-database layer: PostgreSQL (production) or built-in node:sqlite (dev/single-file).
// Same schema, parameterized queries. `pg` uses $1 placeholders; sqlite uses ?.
// We normalize by writing SQL with ? and converting to $n for pg.
import fs from "node:fs";
import path from "node:path";
import { config } from "./config.js";

const usePg = config.databaseUrl.startsWith("postgres");

let pgPool = null;
let sqliteDb = null;

function toPg(sql) {
  let i = 0;
  return sql.replace(/\?/g, () => `$${++i}`);
}

export async function initDb() {
  fs.mkdirSync(config.dataDir, { recursive: true });
  if (usePg) {
    const { default: pg } = await import("pg");
    pgPool = new pg.Pool({ connectionString: config.databaseUrl });
    await pgPool.query("SELECT 1");
  } else {
    const { DatabaseSync } = await import("node:sqlite");
    sqliteDb = new DatabaseSync(path.join(config.dataDir, "app.db"));
    sqliteDb.exec("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;");
  }
  await migrate();
}

export function isPg() { return usePg; }

function execRaw(sql) {
  if (usePg) return pgPool.query(toPg(sql)).then(() => {});
  sqliteDb.exec(sql);
}

// id columns: TEXT pk (nanoid-ish) to keep pg/sqlite identical without sequences.
export async function migrate() {
  const stmts = [
    `CREATE TABLE IF NOT EXISTS users(
      id TEXT PRIMARY KEY, username TEXT NOT NULL, email TEXT NOT NULL,
      display_name TEXT NOT NULL DEFAULT '', password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user', status TEXT NOT NULL DEFAULT 'active',
      avatar_color TEXT NOT NULL DEFAULT '#5b7cff',
      timezone TEXT NOT NULL DEFAULT 'UTC',
      created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
      last_seen_at TEXT
    )`,
    `CREATE TABLE IF NOT EXISTS sessions(
      id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TEXT NOT NULL, expires_at TEXT NOT NULL, ip TEXT NOT NULL DEFAULT ''
    )`,
    `CREATE TABLE IF NOT EXISTS invitations(
      id TEXT PRIMARY KEY, token_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user',
      created_by TEXT, email_hint TEXT NOT NULL DEFAULT '',
      expires_at TEXT NOT NULL, used_at TEXT, used_by TEXT,
      created_at TEXT NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS courses(
      id TEXT PRIMARY KEY, kind TEXT NOT NULL, title TEXT NOT NULL, slug TEXT NOT NULL,
      dir_name TEXT NOT NULL, has_icon INTEGER NOT NULL DEFAULT 0,
      total_seconds INTEGER NOT NULL DEFAULT 0, lesson_count INTEGER NOT NULL DEFAULT 0,
      page_count INTEGER NOT NULL DEFAULT 0,
      last_scanned_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS content_groups(
      id TEXT PRIMARY KEY, course_id TEXT NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
      parent_id TEXT REFERENCES content_groups(id) ON DELETE CASCADE,
      title TEXT NOT NULL, path_key TEXT NOT NULL,
      depth INTEGER NOT NULL DEFAULT 1, position INTEGER NOT NULL DEFAULT 0,
      sort_key TEXT NOT NULL DEFAULT '',
      is_active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS lessons(
      id TEXT PRIMARY KEY, course_id TEXT NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
      group_id TEXT REFERENCES content_groups(id) ON DELETE SET NULL,
      title TEXT NOT NULL, path_key TEXT NOT NULL, file_name TEXT NOT NULL DEFAULT '',
      position INTEGER NOT NULL DEFAULT 0, sort_key TEXT NOT NULL DEFAULT '',
      duration_secs INTEGER, file_size INTEGER NOT NULL DEFAULT 0,
      is_active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS reading_pages(
      id TEXT PRIMARY KEY, course_id TEXT NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
      group_id TEXT REFERENCES content_groups(id) ON DELETE SET NULL,
      title TEXT NOT NULL, path_key TEXT NOT NULL,
      position INTEGER NOT NULL DEFAULT 0, sort_key TEXT NOT NULL DEFAULT '',
      word_count INTEGER NOT NULL DEFAULT 0, file_size INTEGER NOT NULL DEFAULT 0,
      is_active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS resources(
      id TEXT PRIMARY KEY, course_id TEXT NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
      group_id TEXT REFERENCES content_groups(id) ON DELETE SET NULL,
      lesson_id TEXT REFERENCES lessons(id) ON DELETE SET NULL,
      title TEXT NOT NULL, path_key TEXT NOT NULL, file_name TEXT NOT NULL DEFAULT '',
      kind TEXT NOT NULL DEFAULT 'other', file_size INTEGER NOT NULL DEFAULT 0,
      is_active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS video_progress(
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      lesson_id TEXT NOT NULL REFERENCES lessons(id) ON DELETE CASCADE,
      position_secs REAL NOT NULL DEFAULT 0, duration_secs REAL NOT NULL DEFAULT 0,
      completed INTEGER NOT NULL DEFAULT 0, completed_at TEXT,
      watch_secs REAL NOT NULL DEFAULT 0,
      updated_at TEXT NOT NULL,
      PRIMARY KEY(user_id, lesson_id)
    )`,
    `CREATE TABLE IF NOT EXISTS reading_progress(
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      page_id TEXT NOT NULL REFERENCES reading_pages(id) ON DELETE CASCADE,
      scroll_pct REAL NOT NULL DEFAULT 0, scroll_px INTEGER NOT NULL DEFAULT 0,
      completed INTEGER NOT NULL DEFAULT 0, completed_at TEXT,
      active_secs REAL NOT NULL DEFAULT 0, last_read_at TEXT,
      updated_at TEXT NOT NULL,
      PRIMARY KEY(user_id, page_id)
    )`,
    `CREATE TABLE IF NOT EXISTS learning_sessions(
      id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      course_id TEXT REFERENCES courses(id) ON DELETE SET NULL,
      content_type TEXT NOT NULL DEFAULT 'video', content_id TEXT NOT NULL DEFAULT '',
      tab_id TEXT NOT NULL DEFAULT '',
      started_at TEXT NOT NULL, ended_at TEXT, last_heartbeat_at TEXT NOT NULL,
      active_secs REAL NOT NULL DEFAULT 0
    )`,
    `CREATE TABLE IF NOT EXISTS daily_activity(
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      day TEXT NOT NULL, video_secs REAL NOT NULL DEFAULT 0,
      reading_secs REAL NOT NULL DEFAULT 0, completions INTEGER NOT NULL DEFAULT 0,
      updated_at TEXT NOT NULL,
      PRIMARY KEY(user_id, day)
    )`,
    `CREATE TABLE IF NOT EXISTS course_completions(
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      course_id TEXT NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
      completed_at TEXT NOT NULL, learned_secs REAL NOT NULL DEFAULT 0,
      items_done INTEGER NOT NULL DEFAULT 0, items_total INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY(user_id, course_id)
    )`,
    `CREATE TABLE IF NOT EXISTS user_settings(
      user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      autoplay INTEGER NOT NULL DEFAULT 1, playback_speed REAL NOT NULL DEFAULT 1,
      focus_default INTEGER NOT NULL DEFAULT 0, theme TEXT NOT NULL DEFAULT 'dark',
      updated_at TEXT NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS scan_state(
      id INTEGER PRIMARY KEY CHECK(id=1), last_ok_at TEXT, last_status TEXT NOT NULL DEFAULT 'never',
      last_error TEXT NOT NULL DEFAULT '', course_count INTEGER NOT NULL DEFAULT 0
    )`,
  ];
  for (const s of stmts) execRaw(s);
  execRaw(`INSERT INTO scan_state(id) VALUES(1) ON CONFLICT DO NOTHING`);
  // sqlite doesn't support ON CONFLICT DO NOTHING without target on some builds — fallback:
  try {
    await get("SELECT id FROM scan_state WHERE id=1");
  } catch { /* pg path already inserted */ }
  const idx = [
    `CREATE INDEX IF NOT EXISTS idx_lessons_course ON lessons(course_id)`,
    `CREATE INDEX IF NOT EXISTS idx_pages_course ON reading_pages(course_id)`,
    `CREATE INDEX IF NOT EXISTS idx_groups_course ON content_groups(course_id)`,
    `CREATE INDEX IF NOT EXISTS idx_resources_course ON resources(course_id)`,
    `CREATE INDEX IF NOT EXISTS idx_sessions_user ON learning_sessions(user_id)`,
    `CREATE INDEX IF NOT EXISTS idx_daily_user ON daily_activity(user_id)`,
    `CREATE UNIQUE INDEX IF NOT EXISTS uq_users_username ON users(username)`,
    `CREATE UNIQUE INDEX IF NOT EXISTS uq_users_email ON users(email)`,
    `CREATE UNIQUE INDEX IF NOT EXISTS uq_course_slug ON courses(kind, slug)`,
    `CREATE UNIQUE INDEX IF NOT EXISTS uq_lesson_key ON lessons(course_id, path_key)`,
    `CREATE UNIQUE INDEX IF NOT EXISTS uq_page_key ON reading_pages(course_id, path_key)`,
    `CREATE UNIQUE INDEX IF NOT EXISTS uq_group_key ON content_groups(course_id, path_key)`,
    `CREATE UNIQUE INDEX IF NOT EXISTS uq_resource_key ON resources(course_id, path_key)`,
  ];
  for (const s of idx) { try { execRaw(s); } catch {} }
  await migrateLegacyModules();
  // backfill settings for users missing rows
  try {
    if (usePg) await pgPool.query(`INSERT INTO user_settings(user_id, updated_at) SELECT id, NOW()::text FROM users ON CONFLICT DO NOTHING`);
    else sqliteDb.exec(`INSERT OR IGNORE INTO user_settings(user_id, updated_at) SELECT id, datetime('now') FROM users`);
  } catch {}
}

async function tableExists(name) {
  if (usePg) {
    const r = await get(`SELECT to_regclass(?) AS t`, [`public.${name}`]);
    return !!r?.t;
  }
  return !!(await get(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, [name]));
}
async function columnExists(table, col) {
  if (usePg) {
    return !!(await get(`SELECT 1 FROM information_schema.columns WHERE table_name=? AND column_name=?`, [table, col]));
  }
  const rows = await all(`PRAGMA table_info(${table})`);
  return rows.some((r) => r.name === col);
}

// One-way, idempotent port from the legacy flat `modules` model to recursive
// `content_groups`. Group row IDs are preserved (same ids as old modules) and
// lessons keep their own IDs, so all video/reading progress survives untouched.
async function migrateLegacyModules() {
  try {
    if (!(await tableExists("modules"))) return;
    const legacy = await all(`SELECT * FROM modules`);
    if (!legacy.length) {
      try { execRaw(`DROP TABLE modules`); } catch {}
      return;
    }
    if (!(await columnExists("lessons", "group_id"))) execRaw(`ALTER TABLE lessons ADD COLUMN group_id TEXT`);
    if (!(await columnExists("reading_pages", "group_id"))) execRaw(`ALTER TABLE reading_pages ADD COLUMN group_id TEXT`);
    if (!(await columnExists("reading_pages", "file_size"))) execRaw(`ALTER TABLE reading_pages ADD COLUMN file_size INTEGER NOT NULL DEFAULT 0`);
    for (const m of legacy) {
      const exists = await get(`SELECT id FROM content_groups WHERE id=?`, [m.id]);
      if (!exists) {
        await run(`INSERT INTO content_groups(id, course_id, parent_id, title, path_key, depth, position, sort_key, is_active, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
          [m.id, m.course_id, null, m.title, m.path_key, 1, m.position || 0, m.sort_key || "", m.is_active ?? 1, m.created_at, m.updated_at]);
      }
    }
    if (await columnExists("lessons", "module_id")) {
      await run(`UPDATE lessons SET group_id=module_id WHERE module_id IS NOT NULL AND group_id IS NULL`);
      try { execRaw(`ALTER TABLE lessons DROP COLUMN module_id`); } catch {}
    }
    // verify no lesson still depends on the old table before dropping it
    const dangling = (await columnExists("lessons", "module_id"))
      ? await get(`SELECT COUNT(*) n FROM lessons WHERE module_id IS NOT NULL`) : { n: 0 };
    if (!(dangling?.n > 0)) {
      try { execRaw(`DROP TABLE modules`); } catch {}
    }
  } catch { /* never block boot on migration */ }
}

export async function all(sql, params = []) {
  if (usePg) return (await pgPool.query(toPg(sql), params)).rows;
  const st = sqliteDb.prepare(sql);
  return st.all(...params);
}
export async function get(sql, params = []) {
  if (usePg) return (await pgPool.query(toPg(sql), params)).rows[0] || null;
  const st = sqliteDb.prepare(sql);
  return st.get(...params) || null;
}
export async function run(sql, params = []) {
  if (usePg) { await pgPool.query(toPg(sql), params); return; }
  sqliteDb.prepare(sql).run(...params);
}

export function uid(prefix = "id") {
  const { randomBytes } = requireNodeCrypto();
  return `${prefix}_${randomBytes(12).toString("hex")}`;
}
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
function requireNodeCrypto() { return require("node:crypto"); }

export function nowIso() { return new Date().toISOString(); }
