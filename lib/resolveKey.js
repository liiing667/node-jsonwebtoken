'use strict';

const isPlainObject = require('lodash.isplainobject');
const JsonWebTokenError = require('./JsonWebTokenError');

/**
 * Normalize the value returned by a dynamic key resolver into an atomic
 * `{ key, algorithms, kid }` resolution.
 *
 * A resolver may either return the key material directly (the legacy shape,
 * which keeps working unchanged) or return a plain object describing the
 * resolved key together with the algorithm policy that applies to that
 * specific key:
 *
 *   { key: <secretOrPublicKey>, algorithms: ['RS256', ...], kid: 'id' }
 *
 * When the object shape is used the key and its algorithm policy are
 * consumed together so that a key rotation can never pair a freshly
 * resolved key with a stale algorithm list.
 */
module.exports = function resolveKey(resolved) {
  if (!isPlainObject(resolved) || !Object.prototype.hasOwnProperty.call(resolved, 'algorithms')) {
    return {
      key: resolved,
      algorithms: undefined,
      kid: undefined
    };
  }

  if (!Array.isArray(resolved.algorithms) || resolved.algorithms.length === 0) {
    throw new JsonWebTokenError('key resolver result "algorithms" must be a non-empty array of algorithm names');
  }

  const algorithms = resolved.algorithms.slice();

  for (let index = 0; index < algorithms.length; index++) {
    if (typeof algorithms[index] !== 'string' || algorithms[index].trim() === '') {
      throw new JsonWebTokenError('key resolver result "algorithms" must contain only non-empty strings');
    }
  }

  if (resolved.kid !== undefined && (typeof resolved.kid !== 'string' || resolved.kid.trim() === '')) {
    throw new JsonWebTokenError('key resolver result "kid" must be a non-empty string');
  }

  if (!Object.prototype.hasOwnProperty.call(resolved, 'key')) {
    throw new JsonWebTokenError('key resolver result must contain a "key" property');
  }

  return {
    key: resolved.key,
    algorithms: algorithms,
    kid: resolved.kid
  };
};
