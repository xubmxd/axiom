// Training-path icons: files live with the git-ignored lab content at
// labs/icons/<course-slug>.<ext>, checked at render time (same pattern as
// avatars). Drop in a square PNG/WebP and the catalog card picks it up —
// no restart, no database change.
import fs from "node:fs";
import path from "node:path";
import { labsRoot } from "./definitions.js";

export const ICON_MIME = {
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".webp": "image/webp",
  ".gif": "image/gif",
  // Served for <img> use only, where SVG scripts never execute.
  ".svg": "image/svg+xml",
};

export function iconsDir(root = labsRoot()) {
  return path.join(process.env.LAB_ICONS_DIR || path.join(root, "icons"));
}

export function findLabCourseIcon(slug, root = labsRoot()) {
  if (!/^[a-z0-9][a-z0-9-]*$/.test(String(slug || ""))) return null;
  const dir = iconsDir(root);
  for (const ext of Object.keys(ICON_MIME)) {
    const fp = path.normalize(path.join(dir, `${slug}${ext}`));
    if (fp === dir || !fp.startsWith(dir + path.sep)) continue; // traversal guard
    try {
      const stat = fs.statSync(fp);
      if (stat.isFile() && stat.size > 0 && stat.size <= 2 * 1024 * 1024) {
        return { file: fp, mime: ICON_MIME[ext] };
      }
    } catch { /* try next extension */ }
  }
  return null;
}
