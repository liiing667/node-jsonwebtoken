const jwt = require('../index');
const PS_SUPPORTED = require('../lib/psSupported');
const { validatePssKey, isPssAlgorithm, PSS_PARAMETERS } = require('../lib/pssParams');
const pssCrypto = require('../lib/pssCrypto');
const jws = require('jws');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const expect = require('chai').expect;

if (!PS_SUPPORTED) {
  return;
}

function loadKey(filename) {
  return fs.readFileSync(path.join(__dirname, filename));
}

function loadKeyObject(filename) {
  return crypto.createPrivateKey(loadKey(filename));
}

const rsaPrivateKey = loadKey('priv.pem');
const rsaPublicKey = loadKey('pub.pem');
const pss256PrivateKey = loadKey('rsa-pss-private.pem');
const strictPss256PublicKey = crypto.createPublicKey(loadKey('rsa-pss-mgf256-salt32-public.pem'));
const salt16PrivateKey = loadKey('rsa-pss-mgf256-salt16-private.pem');
const salt16PublicKey = loadKey('rsa-pss-mgf256-salt16-public.pem');
const mgf1PrivateKey = loadKey('rsa-pss-mgf1-salt32-private.pem');
const mgf1PublicKey = loadKey('rsa-pss-mgf1-salt32-public.pem');
const sha384PrivateKey = loadKey('rsa-pss-sha384-private.pem');
const sha384PublicKey = loadKey('rsa-pss-sha384-public.pem');

describe('RSA-PSS parameter identity', function() {
  describe('parameter table', function() {
    it('binds each PS algorithm to one exact PSS parameter set', function() {
      expect(PSS_PARAMETERS).to.deep.equal({
        PS256: { hashAlgorithm: 'sha256', mgf1HashAlgorithm: 'sha256', saltLength: 32 },
        PS384: { hashAlgorithm: 'sha384', mgf1HashAlgorithm: 'sha384', saltLength: 48 },
        PS512: { hashAlgorithm: 'sha512', mgf1HashAlgorithm: 'sha512', saltLength: 64 }
      });
      ['PS256', 'PS384', 'PS512'].forEach(function(algorithm) {
        expect(isPssAlgorithm(algorithm)).to.equal(true);
      });
      ['RS256', 'HS256', 'ES256', undefined].forEach(function(algorithm) {
        expect(isPssAlgorithm(algorithm)).to.equal(false);
      });
    });
  });

  describe('base64url codec', function() {
    it('round trips values with and without padding', function() {
      const withPadding = Buffer.from('YWJjZA==', 'base64');
      expect(pssCrypto.base64UrlDecode('YWJjZA').toString()).to.equal(withPadding.toString());
      expect(pssCrypto.base64UrlDecode('YWJjZA').toString()).to.equal('abcd');

      const noPaddingNeeded = pssCrypto.base64UrlEncode(Buffer.from('abc'));
      expect(noPaddingNeeded.length % 4).to.equal(0);
      expect(pssCrypto.base64UrlDecode(noPaddingNeeded).toString()).to.equal('abc');
    });
  });

  describe('validatePssKey', function() {
    it('ignores non-PSS algorithms', function() {
      expect(function() {
        validatePssKey('RS256', crypto.createPrivateKey(rsaPrivateKey));
        validatePssKey(undefined, crypto.createPrivateKey(rsaPrivateKey));
      }).to.not.throw();
    });

    it('ignores keys without an asymmetric key type', function() {
      expect(function() {
        validatePssKey('PS256', { asymmetricKeyType: undefined });
        validatePssKey('PS256', undefined);
      }).to.not.throw();
    });

    it('accepts a generic rsa key because parameters are pinned explicitly', function() {
      expect(function() {
        validatePssKey('PS256', crypto.createPrivateKey(rsaPrivateKey));
      }).to.not.throw();
    });

    it('fails closed when the runtime cannot inspect rsa-pss key details', function() {
      const pssParams = require('../lib/pssParams');
      try {
        pssParams.__setRuntimeCapabilities({ rsaPssKeyDetailsSupported: false });
        expect(function() {
          validatePssKey('PS256', loadKeyObject('rsa-pss-private.pem'));
        }).to.throw('cannot be inspected on this Node.js runtime');
      } finally {
        pssParams.__setRuntimeCapabilities({ rsaPssKeyDetailsSupported: true });
      }

      try {
        pssParams.__setRuntimeCapabilities({ asymmetricKeyDetailsSupported: false });
        expect(function() {
          validatePssKey('PS256', loadKeyObject('rsa-pss-private.pem'));
        }).to.throw('cannot be inspected on this Node.js runtime');
      } finally {
        pssParams.__setRuntimeCapabilities({ asymmetricKeyDetailsSupported: true });
      }
    });

    it('accepts an rsa-pss key whose parameters exactly match the alg', function() {
      expect(function() {
        validatePssKey('PS256', loadKeyObject('rsa-pss-private.pem'));
      }).to.not.throw();
    });

    it('rejects an rsa-pss key with the wrong salt length', function() {
      expect(function() {
        validatePssKey('PS256', crypto.createPrivateKey(salt16PrivateKey));
      }).to.throw('RSA-PSS parameters do not meet the requirements of "alg" PS256');
    });

    it('rejects an rsa-pss key with the wrong MGF1 hash', function() {
      expect(function() {
        validatePssKey('PS256', crypto.createPrivateKey(mgf1PrivateKey));
      }).to.throw('RSA-PSS parameters do not meet the requirements of "alg" PS256');
    });

    it('rejects an rsa-pss key with the wrong message digest', function() {
      expect(function() {
        validatePssKey('PS256', crypto.createPrivateKey(sha384PrivateKey));
      }).to.throw('RSA-PSS parameters do not meet the requirements of "alg" PS256');
      expect(function() {
        validatePssKey('PS512', crypto.createPrivateKey(sha384PrivateKey));
      }).to.throw('RSA-PSS parameters do not meet the requirements of "alg" PS512');
    });

    it('rejects the key even when key type validation is bypassed', function() {
      const token = jwt.sign({ foo: 'bar' }, pss256PrivateKey, { algorithm: 'PS256' });
      expect(function() {
        jwt.verify(token, salt16PublicKey, {
          algorithms: ['PS256'],
          allowInvalidAsymmetricKeyTypes: true
        });
      }).to.throw('RSA-PSS parameters do not meet the requirements of "alg" PS256');
    });
  });

  describe('signing and verifying with a generic rsa key', function() {
    ['PS256', 'PS384', 'PS512'].forEach(function(algorithm) {
      it('round trips ' + algorithm + ' with the RFC 7518 parameter identity', function() {
        const token = jwt.sign({ foo: 'bar' }, rsaPrivateKey, { algorithm });
        const decoded = jwt.verify(token, rsaPublicKey, { algorithms: [algorithm] });
        expect(decoded.foo).to.equal('bar');
      });

      it('round trips ' + algorithm + ' asynchronously', function(done) {
        jwt.sign({ foo: 'bar' }, rsaPrivateKey, { algorithm }, function(error, token) {
          expect(error).to.equal(null);
          jwt.verify(token, rsaPublicKey, { algorithms: [algorithm] }, function(verifyError, decoded) {
            expect(verifyError).to.equal(null);
            expect(decoded.foo).to.equal('bar');
            done();
          });
        });
      });
    });

    it('round trips string and buffer payloads through the PSS path', function() {
      const stringToken = jwt.sign('plain', rsaPrivateKey, { algorithm: 'PS256' });
      expect(jwt.verify(stringToken, rsaPublicKey, { algorithms: ['PS256'] })).to.equal('plain');

      const bufferToken = jwt.sign(Buffer.from('buffered'), rsaPrivateKey, { algorithm: 'PS256' });
      expect(jwt.verify(bufferToken, rsaPublicKey, { algorithms: ['PS256'] })).to.equal('buffered');
    });

    it('enforces the minimum key size on the synchronous and asynchronous PSS paths', function() {
      const smallKey = crypto.generateKeyPairSync('rsa', { modulusLength: 1024 }).privateKey;
      expect(function() {
        jwt.sign({ foo: 'bar' }, smallKey, { algorithm: 'PS256' });
      }).to.throw('minimum key size of 2048 bits for PS256');

      jwt.sign({ foo: 'bar' }, smallKey, {
        algorithm: 'PS256',
        allowInsecureKeySizes: true
      }, function(error, token) {
        expect(error).to.equal(null);
        expect(token.split('.')).to.have.length(3);
      });
    });

    it('produces signatures using MGF1 with the same hash as the alg, not the SHA-1 platform default', function() {
      const token = jwt.sign({ foo: 'bar' }, rsaPrivateKey, { algorithm: 'PS256' });
      const securedInput = token.split('.').slice(0, 2).join('.');
      const signature = token.split('.')[2];
      expect(pssCrypto.verify('PS256', securedInput, signature, strictPss256PublicKey)).to.equal(true);

      const mgf1OnlyPublicKey = crypto.createPublicKey(mgf1PublicKey);
      expect(pssCrypto.verify('PS256', securedInput, signature, mgf1OnlyPublicKey)).to.equal(false);
    });

    it('uses a fixed digest-length salt instead of any-length auto detection', function() {
      const token = jwt.sign({ foo: 'bar' }, rsaPrivateKey, { algorithm: 'PS256' });
      const securedInput = token.split('.').slice(0, 2).join('.');
      const signature = token.split('.')[2];

      function verifyWithSaltLength(saltLength) {
        const verifier = crypto.createVerify('RSA-SHA256');
        verifier.update(securedInput);
        let encoded = signature;
        const padding = 4 - (encoded.length % 4);
        if (padding !== 4) {
          encoded += '='.repeat(padding);
        }
        const rawSignature = Buffer.from(encoded.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
        return verifier.verify({
          key: crypto.createPublicKey(rsaPublicKey),
          padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
          mgf1Hash: 'sha256',
          saltLength: saltLength
        }, rawSignature);
      }

      expect(verifyWithSaltLength(crypto.constants.RSA_PSS_SALTLEN_AUTO)).to.equal(true);
      expect(verifyWithSaltLength(32)).to.equal(true);
      expect(verifyWithSaltLength(16)).to.equal(false);

      expect(jwt.verify.bind(null, token, crypto.createPublicKey(salt16PublicKey), {
        algorithms: ['PS256']
      })).to.throw('RSA-PSS parameters do not meet');
    });
  });

  describe('signing and verifying with an rsa-pss key', function() {
    it('accepts a correct PS256 token signed with a matching rsa-pss key', function() {
      const token = jwt.sign({ foo: 'bar' }, pss256PrivateKey, { algorithm: 'PS256' });
      const decoded = jwt.verify(token, pss256PrivateKey, { algorithms: ['PS256'] });
      expect(decoded.foo).to.equal('bar');
    });

    it('rejects signing when the rsa-pss salt length does not match the alg', function() {
      expect(function() {
        jwt.sign({ foo: 'bar' }, salt16PrivateKey, { algorithm: 'PS256' });
      }).to.throw('RSA-PSS parameters do not meet the requirements of "alg" PS256');
    });

    it('rejects signing when the rsa-pss MGF1 hash does not match the alg', function() {
      expect(function() {
        jwt.sign({ foo: 'bar' }, mgf1PrivateKey, { algorithm: 'PS256' });
      }).to.throw('RSA-PSS parameters do not meet the requirements of "alg" PS256');
    });

    it('rejects signing when the rsa-pss digest does not match the alg', function() {
      expect(function() {
        jwt.sign({ foo: 'bar' }, sha384PrivateKey, { algorithm: 'PS256' });
      }).to.throw('RSA-PSS parameters do not meet the requirements of "alg" PS256');
    });

    it('rejects verification under a public rsa-pss key with a different salt length', function() {
      const token = jwt.sign({ foo: 'bar' }, pss256PrivateKey, { algorithm: 'PS256' });
      expect(function() {
        jwt.verify(token, salt16PublicKey, { algorithms: ['PS256'] });
      }).to.throw('RSA-PSS parameters do not meet the requirements of "alg" PS256');
    });

    it('rejects verification under a public rsa-pss key with a different MGF1 hash', function() {
      const token = jwt.sign({ foo: 'bar' }, pss256PrivateKey, { algorithm: 'PS256' });
      expect(function() {
        jwt.verify(token, mgf1PublicKey, { algorithms: ['PS256'] });
      }).to.throw('RSA-PSS parameters do not meet the requirements of "alg" PS256');
    });

    it('rejects verification under a public rsa-pss key with a different digest', function() {
      const token = jwt.sign({ foo: 'bar' }, pss256PrivateKey, { algorithm: 'PS256' });
      expect(function() {
        jwt.verify(token, sha384PublicKey, { algorithms: ['PS256'] });
      }).to.throw('RSA-PSS parameters do not meet the requirements of "alg" PS256');
    });

    it('keeps working through the asynchronous sign and verify path', function(done) {
      jwt.sign({ foo: 'bar' }, pss256PrivateKey, { algorithm: 'PS256' }, function(error, token) {
        expect(error).to.equal(null);
        jwt.verify(token, pss256PrivateKey, { algorithms: ['PS256'] }, function(verifyError, decoded) {
          expect(verifyError).to.equal(null);
          expect(decoded.foo).to.equal('bar');
          done();
        });
      });
    });
  });

  describe('PKCS#1 v1.5 downgrade protection', function() {
    it('rejects an RS256 token when only PS256 is allowed', function() {
      const token = jwt.sign({ foo: 'bar' }, rsaPrivateKey, { algorithm: 'RS256' });
      expect(function() {
        jwt.verify(token, rsaPublicKey, { algorithms: ['PS256'] });
      }).to.throw('invalid algorithm');
    });

    it('rejects a raw PKCS#1 v1.5 signature placed inside a PS256 token', function() {
      const header = pssCrypto.base64UrlEncode(JSON.stringify({ alg: 'PS256', typ: 'JWT' }));
      const payload = pssCrypto.base64UrlEncode(JSON.stringify({ foo: 'bar' }));
      const securedInput = header + '.' + payload;
      const signer = crypto.createSign('RSA-SHA256');
      signer.update(securedInput);
      const pkcs1Signature = signer.sign(crypto.createPrivateKey(rsaPrivateKey));
      const token = securedInput + '.' + pssCrypto.base64UrlEncode(pkcs1Signature);

      expect(function() {
        jwt.verify(token, rsaPublicKey, { algorithms: ['PS256'] });
      }).to.throw('invalid signature');
    });

    it('rejects a PSS signature when verified as RS256', function() {
      const token = jwt.sign({ foo: 'bar' }, rsaPrivateKey, { algorithm: 'PS256' });
      const header = pssCrypto.base64UrlEncode(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
      const downgradedToken = header + '.' + token.split('.').slice(1).join('.');

      expect(function() {
        jwt.verify(downgradedToken, rsaPublicKey, { algorithms: ['RS256'] });
      }).to.throw('invalid signature');
    });

    it('never routes PS algorithms through the PKCS#1 v1.5 jws verifier', function() {
      const token = jwt.sign({ foo: 'bar' }, rsaPrivateKey, { algorithm: 'PS256' });
      const originalVerify = jws.verify;
      let jwsVerifyCalled = false;
      jws.verify = function() {
        jwsVerifyCalled = true;
        return originalVerify.apply(jws, arguments);
      };
      try {
        jwt.verify(token, rsaPublicKey, { algorithms: ['PS256'] });
      } finally {
        jws.verify = originalVerify;
      }
      expect(jwsVerifyCalled).to.equal(false);
    });

    it('decodes base64url signatures whose length is a multiple of four', function() {
      const token = jwt.sign({ foo: 'bar' }, rsaPrivateKey, { algorithm: 'PS256' });
      const securedInput = token.split('.').slice(0, 2).join('.');
      const signature = token.split('.')[2];
      const decoded = pssCrypto.verify('PS256', securedInput, signature, crypto.createPublicKey(rsaPublicKey));
      expect(decoded).to.equal(true);

      const reEncoded = pssCrypto.base64UrlEncode(Buffer.from(signature, 'base64'));
      expect(pssCrypto.verify('PS256', securedInput, reEncoded, crypto.createPublicKey(rsaPublicKey))).to.equal(true);
    });
  });
});
