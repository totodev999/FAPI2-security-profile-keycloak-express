import fs from 'fs';
import forge from 'node-forge';
import { convertPkcs1ToPkcs8Pem } from './convertToPkcs8.js';

/**
 * Extracts a private key and a certificate in PEM format from a .p12 file.
 * @param p12Path - The path of a .p12 file
 * @param p12Password - The password of the .p12 file
 * @returns { privateKeyPem: string; certificatePem: string }
 */
export function extractPemFromP12(
  p12Path: string,
  p12Password: string
): { privateKeyPem: string; certificatePem: string } {
  // Read the .p12 file
  const p12Buffer: Buffer = fs.readFileSync(p12Path);

  // convert binary data to ASN.1 object
  const p12Asn1 = forge.asn1.fromDer(forge.util.binary.raw.encode(p12Buffer));

  // Parse the PKCS#12 object
  const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, p12Password);

  let privateKey: forge.pki.PrivateKey | undefined = undefined;
  let certificate: forge.pki.Certificate | undefined = undefined;

  // Search for safe contents in PKCS#12
  for (const safeContent of p12.safeContents) {
    for (const safeBag of safeContent.safeBags) {
      if (safeBag.type === forge.pki.oids.pkcs8ShroudedKeyBag) {
        privateKey = safeBag.key;
      } else if (safeBag.type === forge.pki.oids.certBag) {
        certificate = safeBag.cert;
      }
    }
  }

  if (privateKey && certificate) {
    const pkcs1Pem: string = forge.pki.privateKeyToPem(privateKey);
    const pkcs8Pem: string = convertPkcs1ToPkcs8Pem(pkcs1Pem);
    const certificatePem: string = forge.pki.certificateToPem(certificate);
    return { privateKeyPem: pkcs8Pem, certificatePem };
  } else {
    throw new Error('秘密鍵または証明書が見つかりませんでした。');
  }
}
