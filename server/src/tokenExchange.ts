// src/tokenExchange.ts

import axios from 'axios';
import { generateDPoPProof } from './dpopProof.js';
import { generateClientAssertion } from './generateClientAssertion.js';

/**
 * Retrieving an access token using the authorization code.
 * @param tokenEndpoint - The URL of a Token endpoint
 * @param clientId - client_id
 * @param redirectUri - redirect_uri
 * @param code - authorization code
 * @param code_verifier - PKCE code verifier
 * @param privateKeyPath - The path of a private key file in PKCS#8 format
 * @param publicJwkPath - The path of a public key file in JWK format
 * @returns { Promise<any> } - The response of the token endpoint
 */
export async function exchangeCodeForToken({
  tokenEndpoint,
  clientId,
  redirectUri,
  code,
  code_verifier,
  privateKeyPemForPrivateKeyJWT,
  privateKeyForDPoPPem,
  publicJwkForDPoPP,
}: {
  tokenEndpoint: string;
  clientId: string;
  redirectUri: string;
  code: string;
  code_verifier: string;
  privateKeyPemForPrivateKeyJWT: string;
  privateKeyForDPoPPem: string;
  publicJwkForDPoPP: object;
}): Promise<any> {
  // Generate private_key_JWT
  const clientAssertion = generateClientAssertion(
    clientId,
    tokenEndpoint,
    privateKeyPemForPrivateKeyJWT
  );

  // Generate DPoP Proof
  const dpopProof = generateDPoPProof(
    'POST',
    tokenEndpoint,
    privateKeyForDPoPPem,
    publicJwkForDPoPP
  );

  const params = new URLSearchParams();
  params.append('grant_type', 'authorization_code');
  params.append('client_id', clientId);
  params.append('code', code);
  params.append('redirect_uri', redirectUri); // I'm not sure why this is needed
  params.append(
    'client_assertion_type',
    'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
  );
  params.append('client_assertion', clientAssertion);
  params.append('code_verifier', code_verifier);

  try {
    const response = await axios.post(tokenEndpoint, params.toString(), {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        DPoP: dpopProof, // include DPoP header
      },
    });

    if (response.status === 200 && response.data.access_token) {
      return response.data;
    } else {
      throw new Error('Invalid token response');
    }
  } catch (error: any) {
    throw new Error(
      `Token exchange failed: ${
        error.response ? JSON.stringify(error.response.data) : error.message
      }`
    );
  }
}
