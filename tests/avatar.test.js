import { describe, it } from "node:test";
import assert from "node:assert/strict";

const png1x1 = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";
const toUrl = (mime, buf) => `data:${mime};base64,${buf.toString("base64")}`;

describe("avatar upload validation", () => {
  it("accepts a real PNG data URL", async () => {
    const { parseAvatarUpload } = await import("../server/avatar.js");
    const r = parseAvatarUpload(png1x1);
    assert.equal(r.ext, "png");
    assert.ok(r.buffer.length > 0);
  });
  it("sniffs the true type from magic bytes", async () => {
    const { parseAvatarUpload } = await import("../server/avatar.js");
    const jpg = toUrl("image/jpeg", Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10]));
    assert.equal(parseAvatarUpload(jpg).ext, "jpg");
    const gif = toUrl("image/gif", Buffer.from("GIF89a" + "...."));
    assert.equal(parseAvatarUpload(gif).ext, "gif");
    const webp = toUrl("image/webp", Buffer.concat([Buffer.from("RIFF"), Buffer.alloc(4), Buffer.from("WEBP")]));
    assert.equal(parseAvatarUpload(webp).ext, "webp");
  });
  it("rejects SVG, non-images and magic mismatches", async () => {
    const { parseAvatarUpload } = await import("../server/avatar.js");
    assert.throws(() => parseAvatarUpload("data:image/svg+xml;base64,PHN2Zz48L3N2Zz4="), /PNG, JPG/);
    assert.throws(() => parseAvatarUpload("data:text/plain;base64,aGVsbG8="), /PNG, JPG/);
    assert.throws(() => parseAvatarUpload(toUrl("image/png", Buffer.from("not-an-image-bytes"))), /readable/);
    assert.throws(() => parseAvatarUpload("not-a-data-url"), /PNG, JPG/);
  });
  it("enforces the size cap", async () => {
    const { parseAvatarUpload } = await import("../server/avatar.js");
    assert.throws(() => parseAvatarUpload(png1x1, 10), /under/);
  });
  it("builds safe filenames only", async () => {
    const { avatarFileName } = await import("../server/avatar.js");
    assert.equal(avatarFileName("u_abc123", "png"), "u_abc123.png");
    assert.throws(() => avatarFileName("../../etc", "png"), /Invalid user/);
    assert.throws(() => avatarFileName("u_abc", "svg"), /Unsupported/);
  });
});
