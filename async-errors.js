// ---------------------------------------------------------------------------
// Express 4 predates async route handlers: if one returns a rejected promise,
// Express never sees the error. The request hangs until the client times out
// and Node reports an unhandled rejection (which, on newer Node, terminates
// the process by default).
//
// Moving the storage layer to Postgres makes every route handler async, so
// this stops being a theoretical concern — a dropped database connection would
// hang requests instead of returning 500.
//
// This patches Layer.handle_request to forward a rejected promise to next(err),
// which is exactly what Express 5 does natively. It is a faithful copy of
// Express 4's own implementation with the promise branch added, so synchronous
// behaviour is unchanged.
//
// Import this once, before the routes are declared.
// ---------------------------------------------------------------------------
import { createRequire } from 'module';
const require = createRequire(import.meta.url);

const Layer = require('express/lib/router/layer.js');

Layer.prototype.handle_request = function handle(req, res, next) {
  const fn = this.handle;

  // Error-handling middleware (err, req, res, next) is not a request handler.
  if (fn.length > 3) return next();

  try {
    const ret = fn(req, res, next);
    // The only addition: surface async failures to the error pipeline.
    if (ret && typeof ret.then === 'function') {
      ret.then(undefined, next);
    }
  } catch (err) {
    next(err);
  }
};

// Final safety net. Anything that still escapes (a rejection outside a request,
// e.g. in a setInterval) gets logged rather than killing a live server.
process.on('unhandledRejection', (reason) => {
  console.error('[unhandledRejection]', reason instanceof Error ? reason.stack : reason);
});
