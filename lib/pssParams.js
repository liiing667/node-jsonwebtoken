const ASYMMETRIC_KEY_DETAILS_SUPPORTED = require('./asymmetricKeyDetailsSupported');
const RSA_PSS_KEY_DETAILS_SUPPORTED = require('./rsaPssKeyDetailsSupported');

/*
 * Precise RSASSA-PSS parameter identity required by RFC 7518, section 3.5
 * for each "PS*" JWS algorithm. The hash, the MGF1 hash and the salt length
 * are not independent: a token claiming "PS256" must be produced and verified
 * with SHA-256, MGF1-with-SHA-256 and a 32 byte salt, and likewise for the
 * other variants. Accepting any other combination lets the same key material
 * be interpreted under different protocol assumptions.
 */
const PSS_PARAMETERS = {
  PS256: { hashAlgorithm: 'sha256', mgf1HashAlgorithm: 'sha256', saltLength: 32 },
  PS384: { hashAlgorithm: 'sha384', mgf1HashAlgorithm: 'sha384', saltLength: 48 },
  PS512: { hashAlgorithm: 'sha512', mgf1HashAlgorithm: 'sha512', saltLength: 64 }
};

function isPssAlgorithm(algorithm) {
  return Object.prototype.hasOwnProperty.call(PSS_PARAMETERS, algorithm);
}

function getPssParameters(algorithm) {
  return PSS_PARAMETERS[algorithm];
}

/*
 * Indirection kept in module state so the fail-closed branch can be exercised
 * on runtimes (such as current Node) where the key details are always
 * available. The values track the real platform capability by default.
 */
let runtimeCapabilities = {
  asymmetricKeyDetailsSupported: ASYMMETRIC_KEY_DETAILS_SUPPORTED,
  rsaPssKeyDetailsSupported: RSA_PSS_KEY_DETAILS_SUPPORTED
};

/*
 * Asserts that the key can be bound to the precise PSS parameter identity of
 * the claimed "alg".
 *
 * Generic "rsa" keys do not carry PSS parameters, so the exact parameters are
 * supplied explicitly by the sign/verify operations instead of being inferred
 * from platform defaults.
 *
 * "rsa-pss" keys carry their own parameters which always take precedence at the
 * crypto layer. They must match the claimed "alg" exactly. When the key details
 * cannot be inspected (Node < 16.9.0) the parameters cannot be proven, so the
 * operation fails closed rather than being accepted under an unverifiable
 * protocol assumption.
 */
function validatePssKey(algorithm, key) {
  if (!isPssAlgorithm(algorithm)) {
    return;
  }

  const keyType = key && key.asymmetricKeyType;

  if (keyType === 'rsa') {
    return;
  }

  if (keyType !== 'rsa-pss') {
    return;
  }

  if (!runtimeCapabilities.asymmetricKeyDetailsSupported ||
      !runtimeCapabilities.rsaPssKeyDetailsSupported) {
    throw new Error(
      `Invalid key for this operation, the RSA-PSS parameters of the key cannot be inspected on this Node.js runtime, so the requirements of "alg" ${algorithm} cannot be enforced.`
    );
  }

  const details = key.asymmetricKeyDetails;
  const expected = PSS_PARAMETERS[algorithm];
  const { hashAlgorithm, mgf1HashAlgorithm, saltLength } = details;

  if (
    hashAlgorithm !== expected.hashAlgorithm ||
    mgf1HashAlgorithm !== expected.mgf1HashAlgorithm ||
    saltLength !== expected.saltLength
  ) {
    throw new Error(
      `Invalid key for this operation, its RSA-PSS parameters do not meet the requirements of "alg" ${algorithm}.`
    );
  }
}

module.exports = {
  PSS_PARAMETERS,
  isPssAlgorithm,
  getPssParameters,
  validatePssKey,
  __setRuntimeCapabilities(overrides) {
    runtimeCapabilities = Object.assign({}, runtimeCapabilities, overrides);
  }
};
