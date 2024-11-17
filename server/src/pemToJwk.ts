import { importSPKI, exportJWK } from 'jose';
import { readFileSync } from 'fs';

/**
 * Convert a public key in PEM format to JWK format.
 * @param pemPath - The path of a public key file in PEM format
 * @returns {Promise<any>} - The public key in JWK format
 */
export async function pemToJwk(pemPath: string): Promise<any> {
  const pem = readFileSync(pemPath, 'utf-8');
  console.log('pem', pem);
  const key = await importSPKI(pem, 'PS256');
  const jwk = await exportJWK(key);
  return jwk;
}
