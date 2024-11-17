import axios from 'axios';
import { generateDPoPProof } from './dpopProof.js';
import { generateClientAssertion } from './generateClientAssertion.js';

/**
 * Pushed Authorization Request (PAR) を実行します。
 * @param parEndpoint - The URL of a PAR endpoint
 * @param clientId - client_id
 * @param redirectUri - redirect_uri
 * @param scope - scope
 * @param state - state(random string)
 * @param codeChallenge - code_challenge (PKCE)
 * @param codeChallengeMethod - code_challenge_method (i.e: 'S256')
 * @param tokenEndpoint - The URL of a Token endpoint
 * @param privateKeyPath - The path of a private key file in PKCS#8 format
 * @param publicJwk - The public key in JWK format
 * @returns { Promise<string> } - request_uri
 */
export async function performPAR({
  parEndpoint,
  clientId,
  redirectUri,
  scope,
  state,
  codeChallenge,
  codeChallengeMethod = 'S256',
  tokenEndpoint,
  privateKeyPemForPrivateKeyJWT,
  privateKeyForDPoPPem,
  publicJwkForDPoPP,
}: {
  parEndpoint: string;
  clientId: string;
  redirectUri: string;
  scope: string;
  state: string;
  codeChallenge: string;
  codeChallengeMethod?: string;
  tokenEndpoint: string;
  privateKeyPemForPrivateKeyJWT: string;
  privateKeyForDPoPPem: string;
  publicJwkForDPoPP: object;
}): Promise<string> {
  // Generate private_key_JWT
  const clientAssertion = generateClientAssertion(
    clientId,
    tokenEndpoint,
    privateKeyPemForPrivateKeyJWT
  );

  // Generate DPoP Proof
  const dpopProof = generateDPoPProof(
    'POST',
    parEndpoint,
    privateKeyForDPoPPem,
    publicJwkForDPoPP
  );

  const params = new URLSearchParams();
  params.append('client_id', clientId);
  params.append('redirect_uri', redirectUri);
  params.append('scope', scope);
  params.append('state', state);
  params.append('code_challenge', codeChallenge);
  params.append('code_challenge_method', codeChallengeMethod);
  params.append('response_type', 'code');
  params.append(
    'client_assertion_type',
    'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
  );
  params.append('client_assertion', clientAssertion);

  try {
    const response = await axios.post(parEndpoint, params.toString(), {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        DPoP: dpopProof, // include DPoP header
      },
    });

    if (response.status === 201 && response.data.request_uri) {
      return response.data.request_uri;
    } else {
      throw new Error('Invalid PAR response');
    }
  } catch (error: any) {
    throw new Error(
      `PAR failed: ${
        error.response ? JSON.stringify(error.response.data) : error.message
      }`
    );
  }
}
