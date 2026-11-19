const JsonWebTokenError = require('./JsonWebTokenError');

// Header Parameter names registered by RFC 7515 (JWS) and RFC 7516 (JWE).
// The "crit" Header Parameter must never list any of these (RFC 7515, section 10.1.1).
const REGISTERED_HEADER_PARAMETERS = [
  'alg', 'jku', 'jwk', 'kid', 'x5u', 'x5c', 'x5t', 'x5t#S256',
  'typ', 'cty', 'crit', 'enc', 'zip', 'epk', 'apu', 'apv', 'iv',
  'tag', 'p2s', 'p2c'
];

// Normalize the caller-provided "critical" verify option into an object whose
// keys are the implemented extension Header Parameter names and whose values
// are either `true` (acknowledged, no extra processing) or a handler function.
function normalizeCriticalOption(options) {
  const implemented = {};

  if (options.critical === undefined) {
    return implemented;
  }

  const critical = options.critical;

  if (Array.isArray(critical)) {
    critical.forEach(function (name) {
      if (typeof name !== 'string' || name === '') {
        throw new JsonWebTokenError('"critical" option must contain only non-empty strings');
      }
      implemented[name] = true;
    });
    return implemented;
  }

  if (critical === null || typeof critical !== 'object') {
    throw new JsonWebTokenError('"critical" option must be an array or an object');
  }

  Object.keys(critical).forEach(function (name) {
    const handler = critical[name];
    if (handler !== true && typeof handler !== 'function') {
      throw new JsonWebTokenError('"critical" option values must be true or a function');
    }
    implemented[name] = handler;
  });

  return implemented;
}

// Validate the "crit" JOSE Header Parameter (RFC 7515, section 4.1.11 and
// section 10.1.1) before any key lookup, signature verification or claim
// validation happens. Returns a JsonWebTokenError when the token must be
// rejected, otherwise null.
function checkCriticalHeader(header, implemented) {
  const critical = header.crit;

  if (critical === undefined) {
    return null;
  }

  if (!Array.isArray(critical)) {
    return new JsonWebTokenError('"crit" Header Parameter must be an array');
  }

  if (critical.length === 0) {
    return new JsonWebTokenError('"crit" Header Parameter must not be empty');
  }

  const seen = Object.create(null);

  for (let i = 0; i < critical.length; i++) {
    const name = critical[i];

    if (typeof name !== 'string' || name === '') {
      return new JsonWebTokenError('"crit" Header Parameter must contain only non-empty strings');
    }

    if (REGISTERED_HEADER_PARAMETERS.indexOf(name) !== -1) {
      return new JsonWebTokenError('"crit" Header Parameter must not list the registered Header Parameter "' + name + '"');
    }

    if (seen[name]) {
      return new JsonWebTokenError('"crit" Header Parameter must not contain duplicates');
    }
    seen[name] = true;

    if (!Object.prototype.hasOwnProperty.call(implemented, name)) {
      return new JsonWebTokenError('unrecognized critical Header Parameter "' + name + '"');
    }

    if (!Object.prototype.hasOwnProperty.call(header, name)) {
      return new JsonWebTokenError('critical Header Parameter "' + name + '" is not present in the JOSE header');
    }
  }

  return null;
}

// Run the handlers registered for the acknowledged critical Header Parameters.
// This only runs after the signature has been verified, so untrusted header
// content is never processed on an unsigned or tampered token.
function processCritical(header, implemented) {
  if (!Array.isArray(header.crit)) {
    return null;
  }

  for (let i = 0; i < header.crit.length; i++) {
    const name = header.crit[i];
    const handler = implemented[name];

    if (typeof handler === 'function') {
      try {
        handler(header[name], header);
      } catch (err) {
        return new JsonWebTokenError('critical Header Parameter "' + name + '" was rejected: ' + err.message, err);
      }
    }
  }

  return null;
}

module.exports = {
  normalizeCriticalOption,
  checkCriticalHeader,
  processCritical
};
