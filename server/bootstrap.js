import { initDb, get } from "./db.js";
import { createUser } from "./auth.js";
import readline from "node:readline";

await initDb();
const existing = await get(`SELECT COUNT(*) n FROM users WHERE role='admin'`);
if (existing?.n > 0) { console.log("An admin already exists — refusing to bootstrap."); process.exit(0); }
const [username, email, password, name] = process.argv.slice(2);
let u = username, e = email, p = password, n = name;
if (!u || !e || !p) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const q = (s) => new Promise((r) => rl.question(s, r));
  u = u || await q("username: "); e = e || await q("email: "); n = n || await q("display name: ");
  p = p || await q("password (min 10): "); rl.close();
}
if (!u || !e?.includes("@") || String(p).length < 10) { console.error("Invalid input."); process.exit(1); }
const user = await createUser({ username: u, email: e, displayName: n || u, password: p, role: "admin" });
console.log(`Admin created: @${user.username} (${user.email})`);
process.exit(0);
