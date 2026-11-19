const once = require('lodash.once');

const DEFAULT_SECRET_RESOLVER_TIMEOUT_MS = 10000;

// Runs a user supplied key resolver as a bounded, exactly-once stage:
//  - a synchronous throw is captured and forwarded as a resolution error
//  - the completion callback is invoked at most once even if the resolver
//    calls back repeatedly or both throws and calls back
//  - a timeout bounds the stage; once it has settled (or timed out) the
//    timer is cleared and any late callback is ignored, i.e. the stage is
//    cancelled and can never drive verification again
module.exports = function resolveSecret(getSecret, header, timeoutMs, callback) {
  let timer;

  const finish = once(function (err, secret) {
    clearTimeout(timer);
    callback(err, secret);
  });

  timer = setTimeout(function () {
    finish(new Error('secret or public key callback timed out after ' + timeoutMs + 'ms'));
  }, timeoutMs);

  if (typeof timer.unref === 'function') {
    timer.unref();
  }

  let threwInCallback = false;

  try {
    getSecret(header, function (err, secret) {
      try {
        finish(err, secret);
      } catch (callbackErr) {
        // Errors raised from inside the completion callback (e.g. the
        // synchronous verify path whose done() throws) must propagate; only
        // errors raised by the resolver itself become a resolution error.
        threwInCallback = true;
        throw callbackErr;
      }
    });
  } catch (err) {
    if (threwInCallback) {
      throw err;
    }
    finish(err instanceof Error ? err : new Error('secret or public key callback threw an error: ' + err));
  }
};

module.exports.DEFAULT_SECRET_RESOLVER_TIMEOUT_MS = DEFAULT_SECRET_RESOLVER_TIMEOUT_MS;
