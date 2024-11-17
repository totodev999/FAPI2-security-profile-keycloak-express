import express from 'express';
import * as client from 'openid-client';
import cookie from 'cookie-parser';
import path from 'path';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import { importJWK, jwtVerify, calculateJwkThumbprint } from 'jose';

import { extractPrivateKeyPem } from './extractPrivateKey.js';
import { performPAR } from './par.js';
import { exchangeCodeForToken } from './tokenExchange.js';
import axios from 'axios';
import { generateDPoPProof } from './dpopProof.js';
import { pemToJwk } from './pemToJwk.js';
import { readFileSync } from 'fs';

dotenv.config();
// This project is created as ESM, so we need to use import.meta.dirname to get the __dirname
const __dirname = import.meta.dirname;

// get the private key for private_key_jwt
const privateKeyJWTKeyPath = path.join(__dirname, '../private_key_JWT_key.p12');
const privateKeyJWTKeyPassword = 'password';
const privateKeyJWTKey = extractPrivateKeyPem(
  privateKeyJWTKeyPath,
  privateKeyJWTKeyPassword
);

// get keys for DPoP
const privateKeyForDPoPPemPath = path.join(__dirname, '../dpop_private.pem');
const privateKeyForDPoPPem = readFileSync(privateKeyForDPoPPemPath, 'utf-8');
const publicKeyForDPoPPemPath = path.join(__dirname, '../dpop_public.pem');
const publicJwkForDPoPP = await pemToJwk(publicKeyForDPoPPemPath);
// publicJwk should be like this
// {
//   kty: 'RSA',
//   n: 'n-h5OtFof_ui1bSgB9ktFfXXlw0QHpkFpcwLu-I_hP_uUxZHuv12x3dNfFSZpXtQnIejf2x3aQTUss2tPpwH4mEzfGYmcmp5w10PR7KzBv67FitIaaWIQo2ZEWebicAf51wrpdmcMnjvj-exGqs7xPWAmAVSO9NsS4BG9-6ALO-M0JThJIXQdIo-aTP7u-TVme2_RjIMqI7V_AL96oaJf5Ta5W0UYhNzp2LgQwKbtw5Aa2HlzVeuVfFZlbeWVKPekbFz6g-DlmfNL-IY4_rqLLlHKtBZg_eNZRUg_ARv5IVHFg2GNSYFtf3XzVluAGrQM_ZPptZZ9YoZopE01abnDw',
//   e: 'AQAB',
// };

// settings
const clientId = 'test_app_client';
const keycloakRealm = 'test_realm';
const keycloakUrl = 'http://localhost:8080';
const redirectUri = 'https://localhost:4001/api/authRedirect';
const scope = 'openid';
const tokenEndpoint = `${keycloakUrl}/realms/${keycloakRealm}/protocol/openid-connect/token`;

// PKCE code_verifier
let code_verifier: string = client.randomPKCECodeVerifier();

const app = express();

app.use(cookie());

app.use((req, res, next) => {
  console.log('Request URL:', req.url);
  next();
});

app.get('/api/auth', async (req, res) => {
  // 1. Generating code_challenge. Note)code_verifier is already created when server starts. But this way is just for demonstration.
  const codeChallenge = await client.calculatePKCECodeChallenge(code_verifier);
  const state = Math.random().toString(36).substring(2, 15); // ランダムな状態パラメータ

  // 2. Invoking PAR endpoint
  const parEndpoint = `${keycloakUrl}/realms/${keycloakRealm}/protocol/openid-connect/ext/par/request`;

  const requestUri = await performPAR({
    parEndpoint,
    clientId,
    redirectUri,
    scope,
    state,
    codeChallenge,
    tokenEndpoint,
    privateKeyPemForPrivateKeyJWT: privateKeyJWTKey,
    privateKeyForDPoPPem,
    publicJwkForDPoPP,
  });

  // 3. Redirecting to the authorization endpoint
  res.redirect(
    `${keycloakUrl}/realms/${keycloakRealm}/protocol/openid-connect/auth?request_uri=${requestUri}&client_id=${clientId}`
  );
});

// After authorization, a user will be redirected to this endpoint
app.get('/api/authRedirect', async (req, res): Promise<any> => {
  const { iss, code, state } = req.query;

  // To-Do
  // Check the iss and state
  console.log('iss', iss, 'state', state);

  // 1. Requesting the token endpoint
  const data = await exchangeCodeForToken({
    tokenEndpoint,
    clientId,
    redirectUri,
    code: code as string,
    code_verifier,
    privateKeyPemForPrivateKeyJWT: privateKeyJWTKey,
    privateKeyForDPoPPem,
    publicJwkForDPoPP,
  });

  const userInfoEndpoint =
    'http://localhost:8080/realms/test_realm/protocol/openid-connect/userinfo';
  // DPoP Proofの生成
  const dpopProof = generateDPoPProof(
    'GET',
    userInfoEndpoint,
    privateKeyForDPoPPem,
    publicJwkForDPoPP
  );

  // This should be done at Resource Server. But for demonstration, we will do it here.
  // 1. Checking the DPoP Proof
  const decodedDPoP = jwt.decode(dpopProof, { complete: true });

  const alg = decodedDPoP?.header.alg as jwt.Algorithm;
  const jwkKey = (decodedDPoP?.header as any)?.jwk;

  // If you want to check that the verification is really done, you can insert the wrong key here.
  // jwkKey.n =
  //   'n-h51tFof_ui1bSgB9ktFfXXlw0QHpkFpcwLu-I_hP_uUxZHuv12x3dNfFSZpXtQnIejf2x3aQTUss2tPpwH4mEzfGYmcmp5w10PR7KzBv67FitIaaWIQo2ZEWebicAf51wrpdmcMnjvj-exGqs7xPWAmAVSO9NsS4BG9-6ALO-M0JThJIXQdIo-aTP7u-TVme2_RjIMqI7V_AL96oaJf5Ta5W0UYhNzp2LgQwKbtw5Aa2HlzVeuVfFZlbeWVKPekbFz6g-DlmfNL-IY4_rqLLlHKtBZg_eNZRUg_ARv5IVHFg2GNSYFtf3XzVluAGrQM_ZPptZZ9YoZopE01abnDw';

  const key = await importJWK(jwkKey);
  // If DPoP Proof can be decrypted, that means the sender has the private key.
  const verifyResult = await jwtVerify(dpopProof, key, { algorithms: [alg] });

  // To-Do: In a resource server, you should check the DPoP nonce and the time.
  // To check the DPoP nonce, you can use the jti claim.
  // Every time requests are sent, the DPoP nonce should be different.
  // So you should store the DPoP nonce and check if it is already used.
  console.log('verifyResult', verifyResult);

  // 2. Checking the access token using the DPoP Proof
  const hashedThumbprint = await calculateJwkThumbprint(jwkKey);
  const decodedAccessToken = jwt.decode(data.access_token, { complete: true });
  console.log('hashedThumbprint', hashedThumbprint);
  const jkt = (decodedAccessToken?.payload as any)?.cnf?.jkt;
  // If jkt equals hashedThumbprint and as you checked above, the sender has the private key of DPoP,
  // that means the sender is the right one.
  console.log('jkt', jkt, 'check', jkt === hashedThumbprint);
  // If you should check the time, you can use the iat claim.

  // sending the request to the userinfo endpoint. This request to KeyCloak.
  const userInfo = await axios.get(
    'http://localhost:8080/realms/test_realm/protocol/openid-connect/userinfo',
    {
      headers: {
        Authorization: `Bearer ${data.access_token}`,
        DPoP: dpopProof,
      },
    }
  );
  console.log('userInfo', userInfo.data);
});

export default app;
