// Express 4 does not catch rejected promises from async route handlers —
// they become unhandled rejections and crash the Node process (then the
// next page load fails with ERR_CONNECTION_REFUSED until the container
// restarts). Wrap every async handler so errors reach the error middleware.
export const ah = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// Global safety net: patch Express' Layer so ANY async handler/middleware
// rejection is forwarded to the error handler, even if a route was added
// without an explicit ah() wrapper.
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
try {
  const Layer = require("express/lib/router/layer");
  const orig = Layer.prototype.handle_request;
  if (orig && !orig.__asyncPatched) {
    const wrapped = function (req, res, next) {
      try {
        const ret = orig.call(this, req, res, next);
        if (ret && typeof ret.catch === "function") ret.catch(next);
      } catch (err) { next(err); }
    };
    wrapped.__asyncPatched = true;
    Layer.prototype.handle_request = wrapped;
  }
} catch { /* never block boot on patch failure */ }
