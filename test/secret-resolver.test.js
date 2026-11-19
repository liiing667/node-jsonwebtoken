const assert = require('chai').assert;
const resolveSecret = require('../lib/secretResolver');

describe('secretResolver', function () {
  const header = { alg: 'HS256', kid: 'key-1' };

  it('resolves a key through an asynchronous callback', function (done) {
    const resolver = function (receivedHeader, callback) {
      assert.deepEqual(receivedHeader, header);
      setTimeout(function () {
        callback(null, 'the-secret');
      }, 5);
    };

    resolveSecret(resolver, header, 1000, function (err, secret) {
      assert.isNull(err);
      assert.equal(secret, 'the-secret');
      done();
    });
  });

  it('forwards a callback error as the resolution error', function (done) {
    const resolver = function (receivedHeader, callback) {
      setTimeout(function () {
        callback(new Error('key not found'));
      }, 5);
    };

    resolveSecret(resolver, header, 1000, function (err, secret) {
      assert.instanceOf(err, Error);
      assert.equal(err.message, 'key not found');
      assert.isUndefined(secret);
      done();
    });
  });

  it('converts a synchronous throw into a single resolution error', function (done) {
    const resolver = function () {
      throw new Error('boom');
    };

    resolveSecret(resolver, header, 1000, function (err) {
      assert.instanceOf(err, Error);
      assert.equal(err.message, 'boom');
      done();
    });
  });

  it('wraps a synchronous non-Error throw into an Error', function (done) {
    const resolver = function () {
      throw 'string failure'; // eslint-disable-line no-throw-literal
    };

    resolveSecret(resolver, header, 1000, function (err) {
      assert.instanceOf(err, Error);
      assert.match(err.message, /threw an error/);
      done();
    });
  });

  it('completes exactly once when the resolver calls back repeatedly', function (done) {
    const resolver = function (receivedHeader, callback) {
      callback(null, 'first');
      callback(new Error('second'));
      callback(null, 'third');
    };

    let calls = 0;

    resolveSecret(resolver, header, 1000, function (err, secret) {
      calls++;
      assert.equal(calls, 1);
      assert.isNull(err);
      assert.equal(secret, 'first');
      setTimeout(function () {
        assert.equal(calls, 1);
        done();
      }, 10);
    });
  });

  it('ignores a later success when the resolver first reported an error', function (done) {
    const resolver = function (receivedHeader, callback) {
      callback(new Error('first failure'));
      callback(null, 'late-secret');
    };

    resolveSecret(resolver, header, 1000, function (err, secret) {
      assert.instanceOf(err, Error);
      assert.equal(err.message, 'first failure');
      assert.isUndefined(secret);
      done();
    });
  });

  it('ignores a throw that happens after a successful callback', function (done) {
    const resolver = function (receivedHeader, callback) {
      callback(null, 'the-secret');
      throw new Error('late throw');
    };

    resolveSecret(resolver, header, 1000, function (err, secret) {
      assert.isNull(err);
      assert.equal(secret, 'the-secret');
      done();
    });
  });

  it('times out when the resolver never calls back', function (done) {
    const resolver = function () {};

    resolveSecret(resolver, header, 25, function (err, secret) {
      assert.instanceOf(err, Error);
      assert.match(err.message, /timed out after 25ms/);
      assert.isUndefined(secret);
      done();
    });
  });

  it('cancels a late callback once the timeout has fired', function (done) {
    let resolverCallback;
    const resolver = function (receivedHeader, callback) {
      resolverCallback = callback;
    };

    resolveSecret(resolver, header, 25, function (err, secret) {
      assert.match(err.message, /timed out/);
      resolverCallback(null, 'late-secret');
      setTimeout(function () {
        assert.isUndefined(secret);
        done();
      }, 10);
    });
  });

  it('supports a zero millisecond timeout', function (done) {
    const resolver = function () {};

    resolveSecret(resolver, header, 0, function (err) {
      assert.match(err.message, /timed out after 0ms/);
      done();
    });
  });

  it('does not keep the event loop alive with its timeout timer', function (done) {
    const resolver = function (receivedHeader, callback) {
      setTimeout(function () {
        callback(null, 'the-secret');
      }, 5);
    };

    resolveSecret(resolver, header, 10000, function (err, secret) {
      assert.isNull(err);
      assert.equal(secret, 'the-secret');
      done();
    });
  });

  it('exposes a finite default timeout', function () {
    assert.isNumber(resolveSecret.DEFAULT_SECRET_RESOLVER_TIMEOUT_MS);
    assert.isAbove(resolveSecret.DEFAULT_SECRET_RESOLVER_TIMEOUT_MS, 0);
  });

  it('tolerates a timer without an unref method', function (done) {
    const originalSetTimeout = global.setTimeout;
    global.setTimeout = function (handler) {
      const id = originalSetTimeout(handler, 10000);
      return {
        clear: function () {
          clearTimeout(id);
        }
      };
    };
    const originalClearTimeout = global.clearTimeout;
    global.clearTimeout = function (timer) {
      if (timer && typeof timer.clear === 'function') {
        return timer.clear();
      }
      return originalClearTimeout(timer);
    };

    try {
      resolveSecret(function (receivedHeader, callback) {
        callback(null, 'the-secret');
      }, header, 10000, function (err, secret) {
        assert.isNull(err);
        assert.equal(secret, 'the-secret');
        global.setTimeout = originalSetTimeout;
        global.clearTimeout = originalClearTimeout;
        done();
      });
    } catch (err) {
      global.setTimeout = originalSetTimeout;
      global.clearTimeout = originalClearTimeout;
      throw err;
    }
  });

  it('re-throws an error raised from inside the completion callback', function () {
    const resolver = function (receivedHeader, callback) {
      callback(null, 'the-secret');
    };

    const failure = new Error('from the callback');

    assert.throws(function () {
      resolveSecret(resolver, header, 1000, function () {
        throw failure;
      });
    }, failure);
  });

  it('wraps a falsy non-Error throw into an Error', function (done) {
    const resolver = function () {
      throw undefined; // eslint-disable-line no-throw-literal
    };

    resolveSecret(resolver, header, 1000, function (err) {
      assert.instanceOf(err, Error);
      assert.match(err.message, /threw an error/);
      done();
    });
  });

  it('keeps ignoring duplicate completions after the timer is cleared', function (done) {
    let resolverCallback;
    const resolver = function (receivedHeader, callback) {
      resolverCallback = callback;
    };

    let calls = 0;
    resolveSecret(resolver, header, 10000, function (err, secret) {
      calls++;
      assert.isNull(err);
      assert.equal(secret, 'the-secret');
      setTimeout(function () {
        assert.equal(calls, 1);
        done();
      }, 10);
    });

    resolverCallback(null, 'the-secret');
    resolverCallback(null, 'duplicate-secret');
  });
});
