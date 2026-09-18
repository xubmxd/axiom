// Treat all imported course HTML as untrusted. Server-side sanitizer + reformatter:
// - strips scripts, event handlers, iframes, objects, forms, meta refresh, base
// - allowlists tags/attributes; drops javascript:/data:(non-image) URLs
// - rewrites <img src> to the platform media endpoint; keeps alt
// - rewrites internal <a href *.html> to platform reader routes; external links get rel+target
// - returns { html, title, headings[] } for nav. Client renders natively (no iframe).
const ALLOWED = new Set([
  "h1","h2","h3","h4","h5","h6","p","ul","ol","li","blockquote","pre","code",
  "table","thead","tbody","tr","th","td","strong","em","b","i","u","s","a",
  "img","hr","br","span","div","section","article","figure","figcaption","kbd","mark","sup","sub","dl","dt","dd",
]);
const ATTR = { a: new Set(["href","title"]), img: new Set(["src","alt","title"]), "*": new Set(["id"]) };

function esc(s) {
  return String(s ?? "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

function safeUrl(u) {
  const s = String(u || "").trim();
  if (!s || s.startsWith("#")) return s;
  if (/^(https?:\/\/|mailto:)/i.test(s)) return s;
  if (/^(javascript|data|vbscript|file|ftp):/i.test(s)) return "";
  return s; // relative — caller rewrites
}

function sanitize(rawHtml, { mediaPrefix, linkPrefix, pageDir }) {
  let html = String(rawHtml || "");
  html = html.replace(/<script[\s\S]*?<\/script\s*>/gi, "");
  html = html.replace(/<style[\s\S]*?<\/style\s*>/gi, "");
  html = html.replace(/<!--[\s\S]*?-->/g, "");
  html = html.replace(/<\s*(iframe|object|embed|form|input|button|select|textarea|video|audio|link|meta|base|title)[^>]*>[\s\S]*?<\s*\/\s*\1\s*>/gi, "");
  html = html.replace(/<\s*(iframe|object|embed|form|input|button|select|textarea|video|audio|link|meta|base)[^>]*\/?>/gi, "");
  html = html.replace(/\son\w+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)/gi, "");
  const headings = [];
  html = html.replace(/<\/?([a-zA-Z][a-zA-Z0-9]*)\b([^>]*)>/g, (m, tag, attrs) => {
    const closing = m.startsWith("</");
    tag = tag.toLowerCase();
    if (!ALLOWED.has(tag)) return closing ? "" : "";
    if (closing) return `</${tag}>`;
    let out = "";
    let imgSrc = false, imgAlt = "";
    const attrRe = /([a-zA-Z-]+)\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)/g;
    let am;
    const allowed = new Set([...(ATTR["*"] || []), ...(ATTR[tag] || [])]);
    while ((am = attrRe.exec(attrs))) {
      let name = am[1].toLowerCase(), val = am[2].replace(/^['"]|['"]$/g, "");
      if (!allowed.has(name)) continue;
      if (name === "href") {
        val = safeUrl(val);
        if (!val) continue;
        if (!/^(https?:|mailto:|#)/i.test(val)) {
          // internal relative link -> reader page if .html, else drop to #
          const clean = val.split("#")[0].split("?")[0];
          if (/\.html?$/i.test(clean)) {
            const target = resolveRel(pageDir, clean);
            const hash = val.includes("#") ? "#" + val.split("#")[1] : "";
            val = `${linkPrefix}/${encodeURIComponent(target)}${hash}`;
          } else if (!val.startsWith("#")) {
            val = "#";
          }
          out += ` href="${esc(val)}"`;
        } else {
          const ext = /^https?:/i.test(val) ? ` rel="noopener noreferrer" target="_blank"` : "";
          out += ` href="${esc(val)}"${ext}`;
        }
      } else if (name === "src") {
        if (/^(javascript|data(?!:image\/)|vbscript):/i.test(val)) continue;
        if (/^data:image\//i.test(val)) {
          // Embedded images: keep tiny icons, drop multi-MB base64 photo
          // dumps (a single 68MB course file must never ship to the browser).
          if (val.length > 4096) continue;
          out += ` src="${esc(val)}"`;
          imgSrc = true;
          continue;
        }
        if (/^https?:/i.test(val)) continue; // remote images need the proxy (see below) — never inline
        const target = resolveRel(pageDir, val.split("#")[0].split("?")[0]);
        out += ` src="${mediaPrefix}/${encodeURIComponent(target)}"`;
        imgSrc = true;
      } else if (name === "id" || name === "alt" || name === "title") {
        if (tag === "img" && name === "alt") { imgAlt = val.slice(0, 200); continue; }
        out += ` ${name}="${esc(val.slice(0, 200))}"`;
      }
    }
    if (tag === "img") {
      // A src-less <img> renders as a broken-image icon — never emit one.
      // Missing/blocked images become a quiet captioned placeholder instead.
      if (!imgSrc) {
        return imgAlt
          ? `<figure class="media-missing"><span aria-hidden="true">▦</span><figcaption>${esc(imgAlt)}</figcaption></figure>`
          : "";
      }
      return `<img${out} loading="lazy" alt="${esc(imgAlt)}">`;
    }
    return `<${tag}${out}>`;
  });
  // collect headings for the outline (ids returned so the sidebar can anchor to them)
  html = html.replace(/<(h[123])[^>]*>([\s\S]*?)<\/\1>/gi, (m, t, inner) => {
    const text = inner.replace(/<[^>]+>/g, "").trim().slice(0, 120);
    if (text) {
      const id = "s-" + headings.length + "-" + text.toLowerCase().replace(/[^a-z0-9]+/g, "-").slice(0, 40);
      headings.push({ level: t, text, id });
      const open = m.slice(0, m.indexOf(">")).replace(/\sid=(["'])[^"']*\1/i, "");
      return `${open} id="${id}">${inner}</${t}>`;
    }
    return m;
  });
  // pull <body> if full document
  const body = html.match(/<body[^>]*>([\s\S]*)<\/body\s*>/i);
  if (body) html = body[1];
  // drop empty leftovers
  html = html.replace(/<(div|section|article|span)[^>]*>\s*<\/\1>/gi, "");
  // wide tables from imported docs must scroll internally, never push the page
  html = html.replace(/<table[\s\S]*?<\/table\s*>/gi, (m) => `<div class="tscroll">${m}</div>`);
  // absolute last resort: never ship megabytes of markup to the browser
  if (html.length > 4_000_000) {
    html = html.replace(/<img[^>]*>/gi, "");
  }
  if (html.length > 4_000_000) {
    html = esc(html.slice(0, 2_000_000)) + "<p><em>…content truncated for performance…</em></p>";
  }
  return { html: html.trim(), headings };
}

function resolveRel(baseDir, rel) {
  // posix-style relative resolution inside course (no leading /)
  const parts = [...(baseDir ? baseDir.split("/") : []), ...rel.split("/")];
  const out = [];
  for (const p of parts) {
    if (!p || p === ".") continue;
    if (p === "..") out.pop();
    else out.push(p);
  }
  return out.join("/").replace(/^\/+/, "");
}

export function extractTitle(rawHtml, fallback) {
  const m = String(rawHtml || "").match(/<title[^>]*>([\s\S]*?)<\/title\s*>/i) ||
    String(rawHtml || "").match(/<h1[^>]*>([\s\S]*?)<\/h1\s*>/i);
  const t = m ? m[1].replace(/<[^>]+>/g, "").trim() : "";
  return (t || fallback).slice(0, 200);
}

export function countWords(html) {
  const t = String(html || "").replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
  return t ? t.split(" ").length : 0;
}

export { sanitize };
