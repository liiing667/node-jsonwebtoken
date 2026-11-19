var ResourceLimitError = require('./ResourceLimitError');
var JsonWebTokenError = require('./JsonWebTokenError');

var DEFAULT_LIMITS = Object.freeze({
  // maximum byte length of the complete, serialized JWT
  maxTokenLength: 64 * 1024,
  // maximum byte length of the base64url-encoded header segment
  maxHeaderSegmentLength: 8 * 1024,
  // maximum byte length of the base64url-encoded payload segment
  maxPayloadSegmentLength: 512 * 1024,
  // maximum byte length of the base64url-encoded signature segment
  maxSignatureSegmentLength: 64 * 1024,
  // maximum nesting depth of parsed header/claim objects and arrays
  maxDepth: 12
});

function isLimitDisabled(value) {
  return value === false || value === null;
}

function isValidLimit(value) {
  return isLimitDisabled(value) ||
    value === Infinity ||
    (Number.isInteger(value) && value > 0);
}

function resolveLimits(configured) {
  if (configured === undefined) {
    return DEFAULT_LIMITS;
  }

  if (configured === false || configured === null) {
    return null;
  }

  if (typeof configured !== 'object' || Array.isArray(configured)) {
    throw new JsonWebTokenError('limits must be an object');
  }

  var limits = Object.assign({}, DEFAULT_LIMITS);

  Object.keys(configured).forEach(function (key) {
    if (!Object.prototype.hasOwnProperty.call(DEFAULT_LIMITS, key)) {
      throw new JsonWebTokenError('unknown limit option: ' + key);
    }

    var value = configured[key];

    if (!isValidLimit(value)) {
      throw new JsonWebTokenError('limits.' + key + ' must be a positive integer, Infinity or false');
    }

    limits[key] = isLimitDisabled(value) ? Infinity : value;
  });

  return limits;
}

function checkSegmentLength(name, segment, limit) {
  var length = Buffer.byteLength(segment, 'utf8');

  if (length > limit) {
    throw new ResourceLimitError(
      'jwt ' + name + ' segment exceeds maximum length',
      limit,
      length
    );
  }
}

// Validates the raw token structure and byte budgets before any base64
// decoding or JSON parsing takes place.
function checkRawToken(jwtString, limits) {
  var tokenLength = Buffer.byteLength(jwtString, 'utf8');

  if (tokenLength > limits.maxTokenLength) {
    throw new ResourceLimitError(
      'jwt exceeds maximum token length',
      limits.maxTokenLength,
      tokenLength
    );
  }

  var parts = jwtString.split('.');

  if (parts.length !== 3) {
    throw new JsonWebTokenError('jwt malformed');
  }

  checkSegmentLength('header', parts[0], limits.maxHeaderSegmentLength);
  checkSegmentLength('payload', parts[1], limits.maxPayloadSegmentLength);
  checkSegmentLength('signature', parts[2], limits.maxSignatureSegmentLength);

  return parts;
}

// Iteratively measures nesting depth so deeply nested input cannot overflow
// the call stack while being inspected.
function getNestingDepth(value) {
  var maxDepth = 0;
  var stack = [{value: value, depth: 1}];

  while (stack.length > 0) {
    var item = stack.pop();
    var current = item.value;

    if (current === null || typeof current !== 'object') {
      continue;
    }

    if (item.depth > maxDepth) {
      maxDepth = item.depth;
    }

    if (Array.isArray(current)) {
      current.forEach(function (element) {
        stack.push({value: element, depth: item.depth + 1});
      });
    } else {
      Object.keys(current).forEach(function (key) {
        stack.push({value: current[key], depth: item.depth + 1});
      });
    }
  }

  return maxDepth;
}

function checkDepth(name, value, limit) {
  // Non-object payloads (for example string payloads) have no nesting.
  if (value === null || typeof value !== 'object') {
    return;
  }

  var depth = getNestingDepth(value);

  if (depth > limit) {
    throw new ResourceLimitError(
      'jwt ' + name + ' exceeds maximum nesting depth',
      limit,
      depth
    );
  }
}

// Validates the decoded token structure before signature verification runs.
function checkDecodedToken(decodedToken, limits) {
  checkDepth('header', decodedToken.header, limits.maxDepth);
  checkDepth('payload', decodedToken.payload, limits.maxDepth);
}

module.exports = {
  DEFAULT_LIMITS: DEFAULT_LIMITS,
  resolveLimits: resolveLimits,
  checkRawToken: checkRawToken,
  checkDecodedToken: checkDecodedToken,
  getNestingDepth: getNestingDepth
};
