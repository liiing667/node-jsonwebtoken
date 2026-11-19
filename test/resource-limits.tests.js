const jwt = require('../index');
const expect = require('chai').expect;
const ResourceLimitError = require('../lib/ResourceLimitError');
const JsonWebTokenError = require('../lib/JsonWebTokenError');
const {DEFAULT_LIMITS, getNestingDepth} = require('../lib/resourceLimits');
const {verifyJWTHelper, base64UrlEncode} = require('./test-utils');

function makeToken(header, payload, signature) {
  header = header || {alg: 'HS256', typ: 'JWT'};
  payload = payload === undefined ? {foo: 'bar'} : payload;
  signature = signature === undefined ? 'signature' : signature;

  return [
    base64UrlEncode(JSON.stringify(header)),
    base64UrlEncode(typeof payload === 'string' ? payload : JSON.stringify(payload)),
    signature
  ].join('.');
}

function repeat(char, times) {
  return new Array(times + 1).join(char);
}

describe('verify resource limits', function () {
  describe('default limits', function () {
    it('rejects a token longer than the maximum token length', function (done) {
      const oversizedToken = makeToken({alg: 'HS256'}, {foo: 'bar'}, repeat('a', DEFAULT_LIMITS.maxTokenLength));

      verifyJWTHelper(oversizedToken, 'secret', {}, function (err) {
        expect(err).to.be.an.instanceOf(ResourceLimitError);
        expect(err).to.be.an.instanceOf(JsonWebTokenError);
        expect(err.name).to.equal('ResourceLimitError');
        expect(err.code).to.equal('resource_limit');
        expect(err.message).to.equal('jwt exceeds maximum token length');
        expect(err.limit).to.equal(DEFAULT_LIMITS.maxTokenLength);
        expect(err.value).to.be.at.least(DEFAULT_LIMITS.maxTokenLength);
        done();
      });
    });

    it('rejects an oversized header segment before decoding it', function (done) {
      const oversizedHeader = base64UrlEncode(repeat('a', DEFAULT_LIMITS.maxHeaderSegmentLength));
      const token = [
        oversizedHeader,
        base64UrlEncode(JSON.stringify({foo: 'bar'})),
        'signature'
      ].join('.');

      verifyJWTHelper(token, 'secret', {}, function (err) {
        expect(err).to.be.an.instanceOf(ResourceLimitError);
        expect(err.code).to.equal('resource_limit');
        expect(err.message).to.equal('jwt header segment exceeds maximum length');
        expect(err.limit).to.equal(DEFAULT_LIMITS.maxHeaderSegmentLength);
        done();
      });
    });

    it('rejects an oversized payload segment before parsing it', function (done) {
      const oversizedPayload = base64UrlEncode(repeat('a', 4096));
      const token = [
        base64UrlEncode(JSON.stringify({alg: 'HS256'})),
        oversizedPayload,
        'signature'
      ].join('.');

      verifyJWTHelper(token, 'secret', {limits: {maxPayloadSegmentLength: 1024}}, function (err) {
        expect(err).to.be.an.instanceOf(ResourceLimitError);
        expect(err.message).to.equal('jwt payload segment exceeds maximum length');
        expect(err.limit).to.equal(1024);
        done();
      });
    });

    it('rejects an oversized signature segment', function () {
      const token = makeToken({alg: 'HS256'}, {foo: 'bar'}, repeat('b', 2048));

      expect(() => jwt.verify(token, 'secret', {limits: {maxSignatureSegmentLength: 1024}}))
        .to.throw(ResourceLimitError, 'signature segment exceeds maximum length');
    });

    it('rejects a header nested deeper than the maximum depth', function (done) {
      const depth = DEFAULT_LIMITS.maxDepth + 3;
      let nestedHeader = 'alg';

      for (let i = 0; i < depth; i++) {
        nestedHeader = {kid: nestedHeader};
      }

      nestedHeader.alg = 'HS256';

      const token = makeToken(nestedHeader, {foo: 'bar'});

      verifyJWTHelper(token, 'secret', {}, function (err) {
        expect(err).to.be.an.instanceOf(ResourceLimitError);
        expect(err.message).to.equal('jwt header exceeds maximum nesting depth');
        expect(err.limit).to.equal(DEFAULT_LIMITS.maxDepth);
        expect(err.value).to.equal(getNestingDepth(nestedHeader));
        done();
      });
    });

    it('rejects claims nested deeper than the maximum depth', function (done) {
      const depth = DEFAULT_LIMITS.maxDepth + 1;
      let nestedPayload = 'leaf';

      for (let i = 0; i < depth; i++) {
        nestedPayload = {claim: nestedPayload};
      }

      const token = makeToken({alg: 'HS256'}, nestedPayload);

      verifyJWTHelper(token, 'secret', {}, function (err) {
        expect(err).to.be.an.instanceOf(ResourceLimitError);
        expect(err.message).to.equal('jwt payload exceeds maximum nesting depth');
        expect(err.limit).to.equal(DEFAULT_LIMITS.maxDepth);
        expect(err.value).to.equal(getNestingDepth(nestedPayload));
        done();
      });
    });

    it('rejects deeply nested arrays as well as objects', function () {
      let nested = 'leaf';

      for (let i = 0; i < DEFAULT_LIMITS.maxDepth + 2; i++) {
        nested = [nested];
      }

      const token = makeToken({alg: 'HS256'}, {nested: nested});

      expect(() => jwt.verify(token, 'secret')).to.throw(ResourceLimitError, 'payload exceeds maximum nesting depth');
    });

    it('enforces limits before signature verification', function () {
      const token = makeToken({alg: 'HS256'}, {foo: 'bar'}, repeat('b', DEFAULT_LIMITS.maxSignatureSegmentLength + 1));

      // An invalid key must not matter: the limit error is raised first.
      expect(() => jwt.verify(token, undefined, {algorithms: ['HS256']})).to.throw(ResourceLimitError);
    });
  });

  describe('custom limits', function () {
    it('allows callers to tighten the token length budget', function () {
      const token = jwt.sign({foo: 'bar'}, 'secret');

      expect(() => jwt.verify(token, 'secret', {limits: {maxTokenLength: 10}}))
        .to.throw(ResourceLimitError, 'jwt exceeds maximum token length');
    });

    it('allows callers to loosen the payload budget for reasonably large payloads', function (done) {
      const largePayload = {data: repeat('x', 2 * 1024)};
      const token = jwt.sign(largePayload, 'secret', {noTimestamp: true});

      verifyJWTHelper(token, 'secret', {limits: {maxPayloadSegmentLength: 64 * 1024}}, function (err, decoded) {
        expect(err).to.equal(null);
        expect(decoded).to.deep.equal(largePayload);
        done();
      });
    });

    it('allows a specific limit to be disabled with false', function () {
      const token = makeToken({alg: 'HS256'}, {foo: 'bar'}, repeat('b', 2048));

      // Signature length check disabled, total token budget kept small:
      // processing continues to signature verification.
      expect(() => jwt.verify(token, 'secret', {limits: {maxSignatureSegmentLength: false, maxTokenLength: Infinity}}))
        .to.throw(JsonWebTokenError, 'invalid signature');
    });

    it('allows Infinity as an unlimited value', function () {
      const token = makeToken({alg: 'HS256'}, {foo: 'bar'}, repeat('b', 2048));

      expect(() => jwt.verify(token, 'secret', {limits: {maxSignatureSegmentLength: Infinity, maxTokenLength: Infinity}}))
        .to.throw(JsonWebTokenError, 'invalid signature');
    });

    it('rejects non-object limits configuration', function () {
      const token = jwt.sign({foo: 'bar'}, 'secret');

      expect(() => jwt.verify(token, 'secret', {limits: 'nope'}))
        .to.throw(JsonWebTokenError, 'limits must be an object');
    });

    it('rejects unknown limit keys', function () {
      const token = jwt.sign({foo: 'bar'}, 'secret');

      expect(() => jwt.verify(token, 'secret', {limits: {unknown: 1}}))
        .to.throw(JsonWebTokenError, 'unknown limit option: unknown');
    });

    it('rejects invalid limit values', function () {
      const token = jwt.sign({foo: 'bar'}, 'secret');

      expect(() => jwt.verify(token, 'secret', {limits: {maxDepth: 0}}))
        .to.throw(JsonWebTokenError, 'limits.maxDepth must be a positive integer, Infinity or false');
      expect(() => jwt.verify(token, 'secret', {limits: {maxDepth: -1}}))
        .to.throw(JsonWebTokenError, 'limits.maxDepth must be a positive integer, Infinity or false');
      expect(() => jwt.verify(token, 'secret', {limits: {maxDepth: 1.5}}))
        .to.throw(JsonWebTokenError, 'limits.maxDepth must be a positive integer, Infinity or false');
    });

    it('can be fully disabled with false', function (done) {
      const token = makeToken({alg: 'HS256'}, {foo: 'bar'}, repeat('b', 2048));

      verifyJWTHelper(token, 'secret', {limits: false}, function (err) {
        expect(err).to.be.an.instanceOf(JsonWebTokenError);
        expect(err).to.not.be.an.instanceOf(ResourceLimitError);
        expect(err.message).to.equal('invalid signature');
        done();
      });
    });
  });

  describe('compatibility', function () {
    it('keeps the jwt malformed error for tokens with the wrong number of segments', function (done) {
      verifyJWTHelper('a.b', 'secret', {}, function (err) {
        expect(err).to.be.an.instanceOf(JsonWebTokenError);
        expect(err).to.not.be.an.instanceOf(ResourceLimitError);
        expect(err.message).to.equal('jwt malformed');
        done();
      });
    });

    it('accepts string payloads within the configured budgets', function (done) {
      const token = jwt.sign('plain string payload', 'secret');

      verifyJWTHelper(token, 'secret', {}, function (err, decoded) {
        expect(err).to.equal(null);
        expect(decoded).to.equal('plain string payload');
        done();
      });
    });

    it('accepts non-object payloads without applying a nesting budget', function () {
      const numericToken = jwt.sign(42, 'secret');
      const booleanToken = jwt.sign(true, 'secret');

      expect(() => jwt.verify(numericToken, 'secret')).to.not.throw();
      expect(() => jwt.verify(booleanToken, 'secret')).to.not.throw();
    });

    it('handles nested null values while measuring depth', function (done) {
      const token = jwt.sign({a: {b: null}, c: [null, {d: 1}]}, 'secret', {noTimestamp: true});

      verifyJWTHelper(token, 'secret', {}, function (err, decoded) {
        expect(err).to.equal(null);
        expect(decoded).to.deep.equal({a: {b: null}, c: [null, {d: 1}]});
        done();
      });
    });

    it('verifies normal tokens with identical results synchronously and asynchronously', function (done) {
      const token = jwt.sign({foo: 'bar', iat: 1700000000}, 'secret');

      verifyJWTHelper(token, 'secret', {}, function (err, decoded) {
        expect(err).to.equal(null);
        expect(decoded).to.deep.equal({foo: 'bar', iat: 1700000000});
        done();
      });
    });

    it('only attaches limit/value properties when they are available', function () {
      const error = new ResourceLimitError('boom');

      expect(error).to.be.an.instanceOf(JsonWebTokenError);
      expect(error.name).to.equal('ResourceLimitError');
      expect(error.code).to.equal('resource_limit');
      expect(error.message).to.equal('boom');
      expect(error).to.not.have.property('limit');
      expect(error).to.not.have.property('value');
    });
  });
});
