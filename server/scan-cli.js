import { initDb } from "./db.js";
import { scanAll } from "./scanner.js";
await initDb();
const r = await scanAll(true);
console.log(JSON.stringify(r));
process.exit(r.ok ? 0 : 1);
