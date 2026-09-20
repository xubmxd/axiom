// Profile-picture upload validation — pure helpers (unit-tested).
// Storage itself is file-based (DATA_DIR/avatars/<userId>.<ext>), so no
// schema migration is needed. SVG is rejected: unlike raster formats it can
// carry executable script content.
export const AVATAR_EXTS = ["jpg", "jpeg", "png", "webp", "gif"];
export const AVATAR_MIME = {
  jpg: "image/jpeg", jpeg: "image/jpeg", png: "image/png",
  webp: "image/webp", gif: "image/gif",
};
export const AVATAR_MAX_BYTES = 512 * 1024;

export function sniffImageExt(buf) {
  if (!buf?.length) return null;
  if (buf.length >= 8 && buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47) return "png";
  if (buf.length >= 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return "jpg";
  if (buf.length >= 6 && buf.toString("ascii", 0, 6).startsWith("GIF8")) return "gif";
  if (buf.length >= 12 && buf.toString("ascii", 0, 4) === "RIFF" && buf.toString("ascii", 8, 12) === "WEBP") return "webp";
  return null;
}

// Parses a `data:image/...;base64,...` upload. Returns { ext, buffer } or
// throws an Error with a user-facing message.
export function parseAvatarUpload(dataUrl, maxBytes = AVATAR_MAX_BYTES) {
  const m = /^data:image\/(png|jpe?g|webp|gif);base64,([A-Za-z0-9+/=\s]+)$/.exec(String(dataUrl || "").trim());
  if (!m) throw new Error("Upload a PNG, JPG, WEBP or GIF image.");
  const buf = Buffer.from(m[2].replace(/\s+/g, ""), "base64");
  if (!buf.length || buf.length > maxBytes) throw new Error(`Image must be under ${Math.round(maxBytes / 1024)}KB.`);
  const ext = sniffImageExt(buf);
  if (!ext) throw new Error("That file isn't a readable image.");
  return { ext: ext === "jpeg" ? "jpg" : ext, buffer: buf };
}

export function avatarFileName(userId, ext) {
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(String(userId || ""))) throw new Error("Invalid user.");
  if (!AVATAR_EXTS.includes(ext)) throw new Error("Unsupported image type.");
  return `${userId}.${ext}`;
}
