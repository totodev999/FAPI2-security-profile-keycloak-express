import jwt from 'jsonwebtoken';
import crypto from 'crypto';

/**
 * Create a DPoP Proof JWT.
 * @param method - HTTP Method
 * @param url - URL of the request
 * @param privateKeyPath - Path of the private key file in PKCS#8 format
 * @param publicJwkPath - Path of the public key file in JWK format
 * @returns { string } - DPoP Proof JWT
 */
export function generateDPoPProof(
  method: string,
  url: string,
  privateKey: string,
  publicJwk: object
): string {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    htm: method.toUpperCase(),
    htu: url,
    // This cloud be a DPoP nonce. Or maybe is adding nonce needed?
    jti: crypto.randomUUID(),
    iat: now,
  };

  const signOptions: jwt.SignOptions = {
    algorithm: 'PS256',
    header: {
      typ: 'dpop+jwt',
      alg: 'PS256',
      // @ts-ignore
      jwk: publicJwk,
    },
  };

  const token = jwt.sign(payload, privateKey, signOptions);
  return token;
}
