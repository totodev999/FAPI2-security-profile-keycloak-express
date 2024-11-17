import crypto from 'crypto';

/**
 * Convert PKCS#1 PEM to PKCS#8 PEM.
 * @param pkcs1Pem - PKCS#1 format private key PEM
 * @returns { string } - PKCS#8 format private key PEM
 */
export function convertPkcs1ToPkcs8Pem(pkcs1Pem: string): string {
  // Convert PKCS#1 PEM to PKCS#8 PEM
  const keyObject = crypto.createPrivateKey({
    key: pkcs1Pem,
    format: 'pem',
    type: 'pkcs1',
  });

  // export to PKCS#8 PEM
  const pkcs8Pem = keyObject
    .export({
      format: 'pem',
      type: 'pkcs8',
    })
    .toString();

  return pkcs8Pem;
}
