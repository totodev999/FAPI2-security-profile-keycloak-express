import jwt from 'jsonwebtoken';
import crypto from 'crypto';

/**
 * Generate a signed JWT assertion for client authentication.
 * KeyCloak's Clinet Authenticator is signed JWT, so this is required.
 * @param clientId - client_id
 * @param tokenEndpoint - The URL of a Token endpoint
 * @param privateKeyPem - The private key in PEM format
 * @returns { string } - The signed JWT assertion
 */
export function generateClientAssertion(
  clientId: string,
  tokenEndpoint: string,
  privateKeyPem: string
): string {
  const now = Math.floor(Date.now() / 1000);
  const uuid = crypto.randomUUID();

  const payload = {
    iss: clientId,
    sub: clientId,
    aud: tokenEndpoint,
    exp: now + 300, // 5 minutes
    jti: `jti-${uuid}`,
  };

  const signOptions: jwt.SignOptions = {
    algorithm: 'PS256',
  };

  const token = jwt.sign(payload, privateKeyPem, signOptions);

  return token;
}
