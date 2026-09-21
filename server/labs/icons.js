// Training-path icons: labs/icons/<course-slug>/icon.<ext>, checked at
// render time (same pattern as avatars and course icon.* files). Drop any
// browser-renderable image in as `icon` and the catalog card picks it up —
// no restart, no database change.
import fs from "node:fs";
import path from "node:path";
import { labsRoot } from "./definitions.js";

// Extensions browsers render as images, with their MIME types.
export const ICON_MIME = {
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".webp": "image/webp",
  ".gif": "image/gif",
  ".avif": "image/avif",
  ".bmp": "image/bmp",
  ".ico": "image/x-icon",
  // Served for <img> use only, where SVG scripts never execute.
  ".svg": "image/svg+xml",
};

export function iconsDir(root = labsRoot()) {
  return path.join(process.env.LAB_ICONS_DIR || path.join(root, "icons"));
}

export function findLabCourseIcon(slug, root = labsRoot()) {
  if (!/^[a-z0-9][a-z0-9-]*$/.test(String(slug || ""))) return null;
  const base = iconsDir(root);
  const dir = path.normalize(path.join(base, String(slug)));
  if (dir === base || !dir.startsWith(base + path.sep)) return null; // traversal guard
  let files = [];
  try {
    files = fs.readdirSync(dir).filter((f) => /^icon\./i.test(f)).sort();
  } catch { return null; }
  for (const f of files) {
    const fp = path.normalize(path.join(dir, f));
    if (fp === dir || !fp.startsWith(dir + path.sep)) continue;
    const mime = ICON_MIME[path.extname(f).toLowerCase()];
    if (!mime) continue; // not browser-renderable — skip
    try {
      const stat = fs.statSync(fp);
      if (stat.isFile() && stat.size > 0 && stat.size <= 2 * 1024 * 1024) {
        return { file: fp, mime };
      }
    } catch { /* try next candidate */ }
  }
  return null;
}
