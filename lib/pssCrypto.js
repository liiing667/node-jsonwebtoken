const crypto = require('crypto');
const { getPssParameters } = require('./pssParams');

function base64UrlEncode(input) {
  return Buffer.from(input)
    .toString('base64')
    .replace(new RegExp('=', 'g'), '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function base64UrlDecode(input) {
  let encoded = input.toString();
  const padding = 4 - (encoded.length % 4);
  if (padding !== 4) {
    for (let i = 0; i < padding; i += 1) {
      encoded += '=';
    }
  }
  return Buffer.from(encoded.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

function pssOptions(algorithm) {
  const parameters = getPssParameters(algorithm);
  return {
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    mgf1Hash: parameters.mgf1HashAlgorithm,
    saltLength: parameters.saltLength
  };
}

/*
 * Signs the JWS secured input using the exact PSS parameter identity of the
 * claimed "alg". The MGF1 hash and salt length are always pinned explicitly so
 * that platform or key defaults can never change the produced signature.
 */
function sign(algorithm, securedInput, privateKey) {
  const parameters = getPssParameters(algorithm);
  const signer = crypto.createSign(`RSA-${parameters.hashAlgorithm.toUpperCase()}`);
  signer.update(securedInput);
  const signature = signer.sign(Object.assign({ key: privateKey }, pssOptions(algorithm)));
  return base64UrlEncode(signature);
}

/*
 * Verifies the JWS signature against the exact PSS parameter identity of the
 * claimed "alg". A fixed salt length is used on purpose: RSA_PSS_SALTLEN_AUTO
 * would accept signatures produced with any salt length and therefore break
 * the parameter identity. PKCS#1 v1.5 signatures can never pass because
 * RSA_PKCS1_PSS_PADDING is mandatory.
 */
function verify(algorithm, securedInput, signature, publicKey) {
  const parameters = getPssParameters(algorithm);
  const verifier = crypto.createVerify(`RSA-${parameters.hashAlgorithm.toUpperCase()}`);
  verifier.update(securedInput);
  return verifier.verify(
    Object.assign({ key: publicKey }, pssOptions(algorithm)),
    base64UrlDecode(signature)
  );
}

module.exports = {
  base64UrlEncode,
  base64UrlDecode,
  sign,
  verify
};
