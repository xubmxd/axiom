import { Router } from "express";
import fs from "node:fs";
import path from "node:path";
import { get } from "./db.js";
import { config } from "./config.js";
import { resolveInside } from "./scanner.js";
import { ah } from "./wrap.js";
export const media = Router();

// Pure helper (unit-tested): returns {start,end} or null if unsatisfiable/invalid.
export function parseRange(header, size) {
  const m = /^bytes=(\d*)-(\d*)$/.exec(String(header || "").trim());
  if (!m) return null;
  let start = m[1] !== "" ? Number(m[1]) : NaN;
  let end = m[2] !== "" ? Number(m[2]) : NaN;
  if (isNaN(start)) {
    if (isNaN(end)) return null;
    start = Math.max(0, size - end);
    end = size - 1;
  }
  if (isNaN(end) || end >= size) end = size - 1;
  if (size === 0 || start >= size || start > end) return null;
  return { start, end };
}
media.use(async (req, res, next) => {
  if (!req.user) return res.status(401).send("auth required");
  next();
});

// course icon
media.get("/:cid/icon", ah(async (req, res) => {
  const c = await get(`SELECT * FROM courses WHERE id=?`, [req.params.cid]);
  if (!c) return res.status(404).end();
  let base;
  try { base = resolveInside(c, "."); } catch { return res.status(403).end(); }
  let files = [];
  try { files = fs.readdirSync(base).filter((f) => /^icon\./i.test(f)); } catch { return res.status(404).end(); }
  if (!files.length) return res.status(404).end();
  const fp = resolveInside(c, files[0]);
  res.setHeader("Cache-Control", "public, max-age=86400");
  res.sendFile(fp);
}));

// video stream with range support — never loads whole file into memory
media.get("/:cid/video/:lid", ah(async (req, res) => {
  const l = await get(`SELECT l.*, c.dir_name, c.kind FROM lessons l JOIN courses c ON c.id=l.course_id WHERE l.id=?`, [req.params.lid]);
  if (!l || l.course_id !== req.params.cid) return res.status(404).end();
  let fp;
  try { fp = resolveInside({ kind: l.kind || "video", dir_name: l.dir_name }, l.path_key); }
  catch { return res.status(403).end(); }
  let stat;
  try { stat = fs.statSync(fp); } catch { return res.status(404).send("file missing — rescan library"); }
  if (!stat.isFile()) return res.status(404).end();
  const ext = path.extname(fp).toLowerCase();
  const mime = ext === ".webm" ? "video/webm" : ext === ".mkv" ? "video/x-matroska" : ext === ".mov" ? "video/quicktime" : "video/mp4";
  const range = req.headers.range;
  if (range) {
    const r = parseRange(range, stat.size);
    // Validate BEFORE writeHead — throwing after headers are sent crashes the process.
    if (!r) return res.status(416).set("Content-Range", `bytes */${stat.size}`).end();
    const { start, end } = r;
    res.writeHead(206, {
      "Content-Range": `bytes ${start}-${end}/${stat.size}`,
      "Accept-Ranges": "bytes", "Content-Length": end - start + 1, "Content-Type": mime,
      "Cache-Control": "private, max-age=3600",
    });
    const stream = fs.createReadStream(fp, { start, end });
    stream.on("error", () => { try { res.destroy(); } catch {} });
    // Client navigating to another video aborts the stream: free the fd.
    res.on("close", () => { try { stream.destroy(); } catch {} });
    stream.pipe(res);
  } else {
    res.writeHead(200, { "Content-Length": stat.size, "Content-Type": mime, "Accept-Ranges": "bytes", "Cache-Control": "private, max-age=3600" });
    const stream = fs.createReadStream(fp);
    stream.on("error", () => { try { res.destroy(); } catch {} });
    res.on("close", () => { try { stream.destroy(); } catch {} });
    stream.pipe(res);
  }
}));

// supplementary resource download/view — never executes content.
// HTML is never a resource (it becomes a reading page); refuse it defensively.
const RESOURCE_MIME = {
  ".txt": "text/plain; charset=utf-8", ".md": "text/plain; charset=utf-8",
  ".markdown": "text/plain; charset=utf-8", ".csv": "text/plain; charset=utf-8",
  ".tsv": "text/plain; charset=utf-8", ".json": "application/json",
  ".xml": "text/xml; charset=utf-8", ".yml": "text/plain; charset=utf-8",
  ".yaml": "text/plain; charset=utf-8",
  ".py": "text/plain; charset=utf-8", ".js": "text/plain; charset=utf-8",
  ".ts": "text/plain; charset=utf-8", ".sh": "text/plain; charset=utf-8",
  ".java": "text/plain; charset=utf-8", ".c": "text/plain; charset=utf-8",
  ".cpp": "text/plain; charset=utf-8", ".go": "text/plain; charset=utf-8",
  ".rs": "text/plain; charset=utf-8", ".sql": "text/plain; charset=utf-8",
  ".ps1": "text/plain; charset=utf-8",
  ".srt": "text/plain; charset=utf-8", ".vtt": "text/vtt; charset=utf-8",
  ".pdf": "application/pdf",
  ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
  ".webp": "image/webp", ".gif": "image/gif", ".svg": "image/svg+xml", ".avif": "image/avif",
  ".bmp": "image/bmp", ".jfif": "image/jpeg", ".ico": "image/x-icon",
  ".tif": "image/tiff", ".tiff": "image/tiff",
};
media.get("/:cid/resource/:rid", ah(async (req, res) => {
  const r = await get(`SELECT r.*, c.dir_name, c.kind AS course_kind FROM resources r JOIN courses c ON c.id=r.course_id WHERE r.id=? AND r.is_active=1`, [req.params.rid]);
  if (!r || r.course_id !== req.params.cid) return res.status(404).end();
  const ext = path.extname(r.file_name).toLowerCase();
  if (ext === ".html" || ext === ".htm") return res.status(403).end();
  const mime = RESOURCE_MIME[ext];
  if (!mime) return res.status(403).end(); // allowlist only
  let fp;
  try { fp = resolveInside({ kind: r.course_kind, dir_name: r.dir_name }, r.path_key); }
  catch { return res.status(403).end(); }
  let stat;
  try { stat = fs.statSync(fp); } catch { return res.status(404).send("file missing — rescan library"); }
  if (!stat.isFile()) return res.status(404).end();
  res.setHeader("Content-Type", mime);
  res.setHeader("Content-Length", stat.size);
  res.setHeader("Cache-Control", "private, max-age=3600");
  // text/code/subtitles/images/pdf render inline; archives download
  if (/^\.(zip|rar|7z|tar|gz|epub)$/.test(ext)) {
    res.setHeader("Content-Disposition", `attachment; filename="${r.file_name.replace(/"/g, "")}"`);
  } else {
    res.setHeader("Content-Disposition", `inline; filename="${r.file_name.replace(/"/g, "")}"`);
    res.setHeader("X-Content-Type-Options", "nosniff");
  }
  const stream = fs.createReadStream(fp);
  stream.on("error", () => { try { res.destroy(); } catch {} });
  res.on("close", () => { try { stream.destroy(); } catch {} });
  stream.pipe(res);
}));

// extracted embedded data: images (see reader). Files live under
// DATA_DIR/embedded/<courseId>/<pageId>/img-N.<ext> — never inside courses/.
const EMBEDDED_MIME = {
  ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
  ".gif": "image/gif", ".webp": "image/webp", ".avif": "image/avif",
  ".bmp": "image/bmp", ".ico": "image/x-icon", ".tif": "image/tiff",
  ".tiff": "image/tiff", ".svg": "image/svg+xml",
};
media.get("/:cid/embedded/:pid/:file", ah(async (req, res) => {
  const { cid, pid, file } = req.params;
  if (!/^img-\d+\.[a-z0-9]+$/i.test(file || "")) return res.status(404).end();
  const ext = path.extname(file).toLowerCase();
  const mime = EMBEDDED_MIME[ext];
  if (!mime) return res.status(403).end();
  const page = await get(`SELECT id, course_id FROM reading_pages WHERE id=? AND course_id=? AND is_active=1`, [pid, cid]);
  if (!page) return res.status(404).end();
  const base = path.join(config.dataDir, "embedded", cid, pid);
  const fp = path.normalize(path.join(base, file));
  if (fp !== base && !fp.startsWith(base + path.sep)) return res.status(403).end();
  let stat;
  try { stat = fs.statSync(fp); } catch { return res.status(404).end(); }
  if (!stat.isFile()) return res.status(404).end();
  res.setHeader("Content-Type", mime);
  res.setHeader("Content-Length", stat.size);
  res.setHeader("Cache-Control", "public, max-age=86400");
  res.setHeader("X-Content-Type-Options", "nosniff");
  const stream = fs.createReadStream(fp);
  stream.on("error", () => { try { res.destroy(); } catch {} });
  res.on("close", () => { try { stream.destroy(); } catch {} });
  stream.pipe(res);
}));

// reading assets (images) — only safe image extensions, inside course root.
// NOTE: express 4 wildcards are anonymous — the match lands in req.params[0].
media.get("/:cid/asset/*", ah(async (req, res) => {
  const c = await get(`SELECT * FROM courses WHERE id=?`, [req.params.cid]);
  if (!c) return res.status(404).end();
  const rel = req.params[0] || "";
  if (!/\.(png|jpe?g|webp|gif|svg|avif|bmp|jfif|ico|tiff?)$/i.test(rel)) return res.status(403).end();
  let fp;
  try { fp = resolveInside(c, rel); } catch { return res.status(403).end(); }
  if (!fs.existsSync(fp)) return res.status(404).end();
  res.setHeader("Cache-Control", "public, max-age=86400");
  res.sendFile(fp);
}));
