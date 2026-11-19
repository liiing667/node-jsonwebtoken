'use strict';

const jwt = require('../');
const jws = require('jws');
const expect = require('chai').expect;
const sinon = require('sinon');
const JsonWebTokenError = require('../lib/JsonWebTokenError');
const {normalizeCriticalOption, checkCriticalHeader} = require('../lib/critical');

const SECRET = 'shhhhh';

function signWithHeader(header, payload) {
  return jws.sign({
    header: Object.assign({alg: 'HS256'}, header),
    payload: payload || {},
    secret: SECRET,
    encoding: 'utf8'
  });
}

describe('critical Header Parameter (crit)', function () {
  describe('normalizeCriticalOption', function () {
    it('returns an empty map when no option is provided', function () {
      expect(normalizeCriticalOption({})).to.deep.equal({});
    });

    it('accepts an array of implemented extension names', function () {
      expect(normalizeCriticalOption({critical: ['http://example.invalid/ext']}))
        .to.deep.equal({'http://example.invalid/ext': true});
    });

    it('accepts an object mapping extension names to true', function () {
      expect(normalizeCriticalOption({critical: {'ext': true}}))
        .to.deep.equal({ext: true});
    });

    it('accepts an object mapping extension names to handler functions', function () {
      const handler = function () {};
      expect(normalizeCriticalOption({critical: {ext: handler}}))
        .to.deep.equal({ext: handler});
    });

    [
      ['a non-array/non-object value', 'nope'],
      ['null', null],
      ['an array containing a number', ['ext', 1]],
      ['an array containing an empty string', ['ext', '']],
      ['an object with a string value', {ext: 'yes'}],
      ['an object with a false value', {ext: false}]
    ].forEach(function (scenario) {
      it('rejects ' + scenario[0], function () {
        expect(function () {
          normalizeCriticalOption({critical: scenario[1]});
        }).to.throw(JsonWebTokenError);
      });
    });
  });

  describe('checkCriticalHeader', function () {
    it('passes when the header has no crit parameter', function () {
      expect(checkCriticalHeader({alg: 'HS256'}, {})).to.equal(null);
    });

    it('rejects a crit value that is not an array', function () {
      const err = checkCriticalHeader({alg: 'HS256', crit: 'ext'}, {});
      expect(err).to.be.instanceOf(JsonWebTokenError);
      expect(err.message).to.match(/must be an array/);
    });

    it('rejects an empty crit array', function () {
      const err = checkCriticalHeader({alg: 'HS256', crit: []}, {});
      expect(err).to.be.instanceOf(JsonWebTokenError);
      expect(err.message).to.match(/must not be empty/);
    });

    it('rejects crit entries that are not non-empty strings', function () {
      const err = checkCriticalHeader({alg: 'HS256', crit: ['']}, {'': true});
      expect(err).to.be.instanceOf(JsonWebTokenError);
      expect(err.message).to.match(/non-empty strings/);
    });

    it('rejects crit entries that list a registered Header Parameter', function () {
      const err = checkCriticalHeader({alg: 'HS256', crit: ['kid'], kid: 'k1'}, {kid: true});
      expect(err).to.be.instanceOf(JsonWebTokenError);
      expect(err.message).to.match(/registered Header Parameter/);
    });

    it('rejects duplicate crit entries', function () {
      const err = checkCriticalHeader({alg: 'HS256', crit: ['ext', 'ext'], ext: 1}, {ext: true});
      expect(err).to.be.instanceOf(JsonWebTokenError);
      expect(err.message).to.match(/duplicates/);
    });

    it('rejects critical extensions the caller did not register', function () {
      const err = checkCriticalHeader({alg: 'HS256', crit: ['ext'], ext: 1}, {});
      expect(err).to.be.instanceOf(JsonWebTokenError);
      expect(err.message).to.match(/unrecognized critical Header Parameter/);
    });

    it('rejects crit entries missing from the JOSE header', function () {
      const err = checkCriticalHeader({alg: 'HS256', crit: ['ext']}, {ext: true});
      expect(err).to.be.instanceOf(JsonWebTokenError);
      expect(err.message).to.match(/is not present in the JOSE header/);
    });

    it('passes when every crit entry is implemented and present in the header', function () {
      const err = checkCriticalHeader({alg: 'HS256', crit: ['ext'], ext: 1}, {ext: true});
      expect(err).to.equal(null);
    });
  });

  describe('jwt.verify', function () {
    it('verifies an ordinary token without a crit header unchanged', function () {
      const token = jwt.sign({foo: 'bar'}, SECRET);
      const decoded = jwt.verify(token, SECRET);
      expect(decoded.foo).to.equal('bar');
    });

    it('keeps kid routing working with a function key callback', function (done) {
      const token = jwt.sign({foo: 'bar'}, SECRET, {keyid: 'kid-1'});
      const getKey = sinon.spy(function (header, callback) {
        expect(header.kid).to.equal('kid-1');
        callback(null, SECRET);
      });
      jwt.verify(token, getKey, {}, function (err, decoded) {
        expect(err).to.equal(null);
        expect(decoded.foo).to.equal('bar');
        expect(getKey.calledOnce).to.equal(true);
        done();
      });
    });

    it('rejects a token with an unrecognized critical extension synchronously', function () {
      const token = signWithHeader({crit: ['ext'], ext: 42});
      expect(function () {
        jwt.verify(token, SECRET);
      }).to.throw(JsonWebTokenError, /unrecognized critical Header Parameter "ext"/);
    });

    it('rejects a token with an unrecognized critical extension asynchronously', function (done) {
      const token = signWithHeader({crit: ['ext'], ext: 42});
      jwt.verify(token, SECRET, function (err) {
        expect(err).to.be.instanceOf(JsonWebTokenError);
        expect(err.message).to.match(/unrecognized critical Header Parameter "ext"/);
        done();
      });
    });

    it('does not invoke the key callback for unhandled critical extensions', function (done) {
      const token = signWithHeader({crit: ['ext'], ext: 42});
      const getKey = sinon.spy(function (header, callback) {
        callback(null, SECRET);
      });
      jwt.verify(token, getKey, {}, function (err) {
        expect(err).to.be.instanceOf(JsonWebTokenError);
        expect(getKey.called).to.equal(false);
        done();
      });
    });

    it('rejects a malformed crit header even when the name is registered', function () {
      const token = signWithHeader({crit: []});
      expect(function () {
        jwt.verify(token, SECRET, {critical: {}});
      }).to.throw(JsonWebTokenError, /must not be empty/);
    });

    it('rejects a critical parameter declared in crit but absent from the header', function () {
      const token = signWithHeader({crit: ['ext']});
      expect(function () {
        jwt.verify(token, SECRET, {critical: ['ext']});
      }).to.throw(JsonWebTokenError, /is not present in the JOSE header/);
    });

    it('rejects crit entries naming registered Header Parameters such as alg', function () {
      const token = signWithHeader({crit: ['alg']});
      expect(function () {
        jwt.verify(token, SECRET, {critical: {alg: true}});
      }).to.throw(JsonWebTokenError, /registered Header Parameter/);
    });

    it('rejects a malformed "critical" option before touching the token', function () {
      const token = jwt.sign({foo: 'bar'}, SECRET);
      expect(function () {
        jwt.verify(token, SECRET, {critical: 'nope'});
      }).to.throw(JsonWebTokenError, /"critical" option must be an array or an object/);
    });

    it('verifies a token whose critical extension is registered via an array', function () {
      const token = signWithHeader({crit: ['ext'], ext: 42});
      const decoded = jwt.verify(token, SECRET, {critical: ['ext']});
      expect(decoded).to.not.have.property('crit');
    });

    it('verifies a token whose critical extension is acknowledged via an object map', function () {
      const token = signWithHeader({crit: ['ext'], ext: 42});
      const decoded = jwt.verify(token, SECRET, {critical: {ext: true}});
      expect(decoded).to.exist;
    });

    it('invokes a registered handler after the signature is verified', function () {
      const token = signWithHeader({crit: ['ext'], ext: 42});
      const handler = sinon.spy(function (value, header) {
        expect(value).to.equal(42);
        expect(header.crit).to.deep.equal(['ext']);
      });
      const decoded = jwt.verify(token, SECRET, {critical: {ext: handler}});
      expect(decoded).to.exist;
      expect(handler.calledOnce).to.equal(true);
    });

    it('fails when a registered handler rejects the extension', function () {
      const token = signWithHeader({crit: ['ext'], ext: 42});
      const handler = function () {
        throw new Error('bad extension value');
      };
      expect(function () {
        jwt.verify(token, SECRET, {critical: {ext: handler}});
      }).to.throw(JsonWebTokenError, /critical Header Parameter "ext" was rejected: bad extension value/);
    });

    it('never runs extension handlers for a token with an invalid signature', function () {
      const token = signWithHeader({crit: ['ext'], ext: 42});
      const tampered = token.slice(0, token.lastIndexOf('.')) + '.AAAA';
      const handler = sinon.spy();
      expect(function () {
        jwt.verify(tampered, SECRET, {critical: {ext: handler}});
      }).to.throw(JsonWebTokenError, /invalid signature/);
      expect(handler.called).to.equal(false);
    });

    it('rejects an unsigned "none" token carrying an unhandled critical extension', function () {
      const token = jws.sign({
        header: {alg: 'none', crit: ['ext'], ext: 1},
        payload: {},
        secret: '',
        encoding: 'utf8'
      });
      expect(function () {
        jwt.verify(token, null, {algorithms: ['none']});
      }).to.throw(JsonWebTokenError, /unrecognized critical Header Parameter "ext"/);
    });

    it('accepts an unsigned "none" token with a handled critical extension', function () {
      const token = jws.sign({
        header: {alg: 'none', crit: ['ext'], ext: 1},
        payload: {},
        secret: '',
        encoding: 'utf8'
      });
      const decoded = jwt.verify(token, null, {algorithms: ['none'], critical: ['ext']});
      expect(decoded).to.deep.equal({});
    });

    it('keeps claim validation order intact and runs handlers before claim checks', function () {
      const token = signWithHeader({crit: ['ext'], ext: 1}, {exp: 1});
      const order = [];
      const handler = function () {
        order.push('handler');
      };
      expect(function () {
        jwt.verify(token, SECRET, {
          clockTimestamp: 100,
          critical: {ext: handler}
        });
      }).to.throw(JsonWebTokenError, /jwt expired/);
      expect(order).to.deep.equal(['handler']);
    });
  });
});
