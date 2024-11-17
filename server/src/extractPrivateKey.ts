import fs from 'fs';
import forge from 'node-forge';
import { convertPkcs1ToPkcs8Pem } from './convertToPkcs8.js';

/**
 * Extracts a private key in PEM format from a .p12 file.
 * @param p12Path - The path of a .p12 file
 * @param p12Password - The password of the .p12 file
 * @returns { privateKeyPem: string }
 */
export function extractPrivateKeyPem(
  p12Path: string,
  p12Password: string
): string {
  // Read the .p12 file
  const p12Buffer: Buffer = fs.readFileSync(p12Path);

  // Parse the .p12 file
  const p12Asn1 = forge.asn1.fromDer(forge.util.binary.raw.encode(p12Buffer));
  const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, p12Password);

  let privateKey: forge.pki.PrivateKey | undefined = undefined;

  // Find the private key
  for (const safeContent of p12.safeContents) {
    for (const safeBag of safeContent.safeBags) {
      if (safeBag.type === forge.pki.oids.pkcs8ShroudedKeyBag) {
        privateKey = safeBag.key;
        break;
      }
    }
    if (privateKey) break;
  }

  if (!privateKey) {
    throw new Error('秘密鍵が見つかりませんでした。');
  }

  // PKCS#1 形式の PEM
  const pkcs1Pem = forge.pki.privateKeyToPem(privateKey);

  // PKCS#8 形式に変換
  const pkcs8Pem = convertPkcs1ToPkcs8Pem(pkcs1Pem);

  return pkcs8Pem;
}
