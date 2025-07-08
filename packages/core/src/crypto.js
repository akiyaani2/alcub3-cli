import { generateKeyPairSync, sign as nodeSign, verify as nodeVerify } from 'crypto';

/**
 * Generate an Ed25519 key pair (PEM encoded) for signing and verification.
 */
export const generateKeyPair = async () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    publicKey: publicKey.export({ type: 'spki', format: 'pem' }),
    privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }),
  };
};

/**
 * Sign arbitrary data (string or Buffer) using the provided PEM-encoded private key.
 * Returns a base64 string signature.
 */
export const sign = async (data, privateKeyPem) => {
  const dataBuffer = data instanceof Uint8Array ? data : Buffer.from(JSON.stringify(data));
  const signature = nodeSign(null, dataBuffer, {
    key: privateKeyPem,
    format: 'pem',
    type: 'pkcs8',
  });
  return signature.toString('base64');
};

/**
 * Verify a signature produced by sign(). Returns true if valid.
 */
export const verify = (data, signatureBase64, publicKeyPem) => {
  const dataBuffer = data instanceof Uint8Array ? data : Buffer.from(JSON.stringify(data));
  const sigBuffer = Buffer.from(signatureBase64, 'base64');
  return nodeVerify(null, dataBuffer, {
    key: publicKeyPem,
    format: 'pem',
    type: 'spki',
  }, sigBuffer);
};
