# Summary

This repository is an implementation of FAPI2.0 security profile using DPoP.
This repository is composed of following items.

- Key Cloak
- Node server(Express)
- React(used only for initial authentication)

## Features

1. PAR(Pushed Authorization Request)
2. private_key_JWT
3. PKCE（Proof Key for Code Exchange）
4. DPoP（Demonstration of Proof-of-Possession）
5. Checking Access Token using DPoP

## Creating key pair for DPoP

```
# private key
openssl genpkey -algorithm RSA -out dpop_private.pem -pkeyopt rsa_keygen_bits:2048

# public key
openssl rsa -pubout -in dpop_private.pem -out dpop_public.pem
```

## Using HTTPS in local environment

```
npx local-ssl-proxy --source 4001 --target 4000
```

## Start Express server

```
npm run dev
```

## Setting KeyCloak

KeyCloak's setting is also done for FAPI2.0.  
KeyCloak has the feature called `Client Policy`. And it has the setting for FAPI2.0. But, now only MTLS is implemented.  
So, I created a new `Client Policy` based on `fapi-2-security-profile`.

1. Creating a new Client Policy  
   The name of `Client Policy` is your choice, such as `fapi2-dpop`.
2. Adding Executors

- confidential-client
- secure-client-authenticator  
  Allowed Client Authenticators should be `client-jwt` and `client-x509`.
- secure-client-uris
- secure-signature-algorithm `PS256`
- secure-signature-algorithm-signed-jwt
- consent-required `Auto-configure On`
- full-scope-disabled `Auto-configure On`
- reject-implicit-grant `Auto-configure On`
- pkce-enforcer `Auto-configure On`
- secure-par-content
- dpop-bind-enforcer `Auto-configure On`

This Client Policy is different only in disabling `holder-of-key-enforcer`.

3. Setting Clients
   You can import the settings to your KeyCloak using `keycloak/settings/test_app_client.json`.

4. Creating a key for client-authentication(private_key_JWT)
   Click the Clients tab and select the clientID you created and click it. Then you'll see client settings and click Keys tab. Click the Generate new Keys. Then you'll see "Generate keys?" modal. Select Archive format(I used PKCS12) and enter password. Then the private key automatically download to your browser. And public key is automatically installed into KeyCloak.

5. Creating a user for tests
   Click the Users tab. At the Users screen, click the Add user button. Enter Username and click the Create button.

6. Run KeyCloak using Docker

```
cd keycloak
docker compose up --build
```

Note:
If you see `keycloak/Dockerfile` file, you'll notice the parameter `KC_FEATURES=dpop`. Since DPoP is currently a preview feature, you need to add the environment variable `KC_FEATURES=dpop`.
