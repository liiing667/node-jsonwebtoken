'use strict';

const fs = require('fs');
const path = require('path');
const jwt = require('../');
const expect = require('chai').expect;
const JsonWebTokenError = require('../lib/JsonWebTokenError');

const rsaPrivateKey = fs.readFileSync(path.join(__dirname, 'rsa-private.pem'));
const rsaPublicKey = fs.readFileSync(path.join(__dirname, 'rsa-public.pem'));

describe('dynamic key resolver (tenant key rotation)', function () {
  describe('atomic key resolution result', function () {
    it('verifies a token using the key and algorithm policy returned together', function (done) {
      const token = jwt.sign({foo: 'bar'}, 'rotated-secret', {algorithm: 'HS256', keyid: 'tenant-1-v2'});

      const resolver = function (header, callback) {
        expect(header.kid).to.equal('tenant-1-v2');
        callback(null, {
          kid: 'tenant-1-v2',
          key: 'rotated-secret',
          algorithms: ['HS256']
        });
      };

      jwt.verify(token, resolver, function (err, payload) {
        expect(err).to.be.null;
        expect(payload.foo).to.equal('bar');
        done();
      });
    });

    it('rejects the token when its alg is not declared by the resolved key policy', function (done) {
      const token = jwt.sign({foo: 'bar'}, 'rotated-secret', {algorithm: 'HS256'});

      const resolver = function (header, callback) {
        callback(null, {
          key: 'rotated-secret',
          algorithms: ['HS384', 'HS512']
        });
      };

      jwt.verify(token, resolver, function (err) {
        expect(err).to.be.instanceOf(JsonWebTokenError);
        expect(err.message).to.equal('invalid algorithm');
        done();
      });
    });

    it('uses the resolved algorithm policy for an asymmetric key', function (done) {
      const token = jwt.sign({foo: 'bar'}, rsaPrivateKey, {algorithm: 'RS256'});

      const resolver = function (header, callback) {
        callback(null, {
          key: rsaPublicKey,
          algorithms: ['RS256']
        });
      };

      jwt.verify(token, resolver, function (err, payload) {
        expect(err).to.be.null;
        expect(payload.foo).to.equal('bar');
        done();
      });
    });

    it('rejects an asymmetric token whose alg is outside the resolved key policy', function (done) {
      const token = jwt.sign({foo: 'bar'}, rsaPrivateKey, {algorithm: 'RS256'});

      const resolver = function (header, callback) {
        callback(null, {
          key: rsaPublicKey,
          algorithms: ['PS256']
        });
      };

      jwt.verify(token, resolver, function (err) {
        expect(err).to.be.instanceOf(JsonWebTokenError);
        expect(err.message).to.equal('invalid algorithm');
        done();
      });
    });

    it('lets the resolver policy override a static options.algorithms list', function (done) {
      const token = jwt.sign({foo: 'bar'}, 'rotated-secret', {algorithm: 'HS256'});

      const resolver = function (header, callback) {
        callback(null, {
          key: 'rotated-secret',
          algorithms: ['HS256']
        });
      };

      jwt.verify(token, resolver, {algorithms: ['HS384']}, function (err, payload) {
        expect(err).to.be.null;
        expect(payload.foo).to.equal('bar');
        done();
      });
    });
  });

  describe('rotation failures', function () {
    it('fails verification instead of falling back when the resolver errors', function (done) {
      const token = jwt.sign({foo: 'bar'}, 'old-secret', {algorithm: 'HS256'});

      const resolver = function (header, callback) {
        callback(new Error('key store unavailable'));
      };

      jwt.verify(token, resolver, {algorithms: ['HS256']}, function (err) {
        expect(err).to.be.instanceOf(JsonWebTokenError);
        expect(err.message).to.match(/error in secret or public key callback/);
        done();
      });
    });

    [
      {
        name: 'a non-array algorithms list',
        result: {key: 'secret', algorithms: 'HS256'},
        message: 'key resolver result "algorithms" must be a non-empty array of algorithm names'
      },
      {
        name: 'an empty algorithms list',
        result: {key: 'secret', algorithms: []},
        message: 'key resolver result "algorithms" must be a non-empty array of algorithm names'
      },
      {
        name: 'a non-string algorithm entry',
        result: {key: 'secret', algorithms: ['HS256', 256]},
        message: 'key resolver result "algorithms" must contain only non-empty strings'
      },
      {
        name: 'a missing key property',
        result: {algorithms: ['HS256']},
        message: 'key resolver result must contain a "key" property'
      },
      {
        name: 'an invalid kid',
        result: {key: 'secret', algorithms: ['HS256'], kid: 42},
        message: 'key resolver result "kid" must be a non-empty string'
      }
    ].forEach(function (scenario) {
      it('does not fall back to an old combination for ' + scenario.name, function (done) {
        const token = jwt.sign({foo: 'bar'}, 'old-secret', {algorithm: 'HS256'});

        const resolver = function (header, callback) {
          callback(null, scenario.result);
        };

        jwt.verify(token, resolver, {algorithms: ['HS256']}, function (err) {
          expect(err).to.be.instanceOf(JsonWebTokenError);
          expect(err.message).to.equal(scenario.message);
          done();
        });
      });
    });
  });

  describe('backward compatibility', function () {
    it('keeps working when the resolver returns the key directly', function (done) {
      const token = jwt.sign({foo: 'bar'}, 'legacy-secret', {algorithm: 'HS256'});

      const resolver = function (header, callback) {
        callback(null, 'legacy-secret');
      };

      jwt.verify(token, resolver, {algorithms: ['HS256']}, function (err, payload) {
        expect(err).to.be.null;
        expect(payload.foo).to.equal('bar');
        done();
      });
    });

    it('infers the algorithms for a legacy callback key from the key type', function (done) {
      const token = jwt.sign({foo: 'bar'}, rsaPrivateKey, {algorithm: 'RS256'});

      const resolver = function (header, callback) {
        callback(null, rsaPublicKey);
      };

      jwt.verify(token, resolver, function (err, payload) {
        expect(err).to.be.null;
        expect(payload.foo).to.equal('bar');
        done();
      });
    });

    it('keeps working with a plain static key', function (done) {
      const token = jwt.sign({foo: 'bar'}, 'static-secret', {algorithm: 'HS256'});

      jwt.verify(token, 'static-secret', {algorithms: ['HS256']}, function (err, payload) {
        expect(err).to.be.null;
        expect(payload.foo).to.equal('bar');
        done();
      });
    });
  });

  describe('concurrent requests', function () {
    it('keeps each resolved key paired with its own algorithm policy', function (done) {
      const tokenA = jwt.sign({tenant: 'a'}, 'secret-a', {algorithm: 'HS256'});
      const tokenB = jwt.sign({tenant: 'b'}, 'secret-b', {algorithm: 'HS384'});
      const sharedOptions = {algorithms: ['HS256']};
      let pending = 2;

      const resolver = function (header, callback) {
        if (header.alg === 'HS256') {
          setTimeout(function () {
            callback(null, {key: 'secret-a', algorithms: ['HS256']});
          }, 20);
        } else {
          setTimeout(function () {
            callback(null, {key: 'secret-b', algorithms: ['HS384']});
          }, 5);
        }
      };

      function finished() {
        if (--pending === 0) {
          done();
        }
      }

      jwt.verify(tokenA, resolver, sharedOptions, function (err, payload) {
        expect(err).to.be.null;
        expect(payload.tenant).to.equal('a');
        expect(sharedOptions.algorithms).to.deep.equal(['HS256']);
        finished();
      });

      jwt.verify(tokenB, resolver, sharedOptions, function (err, payload) {
        expect(err).to.be.null;
        expect(payload.tenant).to.equal('b');
        expect(sharedOptions.algorithms).to.deep.equal(['HS256']);
        finished();
      });
    });
  });
});
