---
title: "Registration"
---

# Registration

See the [WebAuthn guide](https://thecopenhagenbook.com/webauthn) in the Copenhagen Book for details on WebAuthn.

Use `navigator.credentials.create()` to create a new credential on the device and send the returned attestation object and client data JSON to the server.

```ts
import { encodeBase64 } from "@oslojs/encoding";

const credential = await navigator.credentials.create({
	publicKey: {
		challenge,
		user: {
			displayName: "User",
			id: userId,
			name: "user@example.com"
		},
		rp: {
			name: "My site"
		},
		pubKeyCredParams: [
			{
				alg: -7, // ECDSA with P-256 and SHA-256
				type: "public-key"
			}
		],
		attestation: "none",
		authenticatorSelection: {
			userVerification: "required"
		}
	}
});

if (!(credential instanceof PublicKeyCredential)) {
	throw new Error("Failed to create public key");
}
if (!(credential.response instanceof AuthenticatorAttestationResponse)) {
	throw new Error("Unexpected error");
}

const response = await fetch("/api/register", {
	method: "POST",
	body: JSON.stringify({
		attestationObject: encodeBase64(new Uint8Array(credential.response.attestationObject)),
		clientDataJSON: encodeBase64(new Uint8Array(credential.response.clientDataJSON))
	})
});
```

On the server, parse the attestation object and client data JSON. For the attestation object, verify the attestation statement format, relying party ID hash, user present and user verified flags, and the algorithm used. For the client data JSON, check the challenge and origin. If all checks passes, store the credential ID, algorithm, and public key alongside the user ID.

We recommend using [`@oslojs/crypto`](https://crypto.oslojs.dev) for handling ECDSA public keys and signatures.

```ts
import {
	parseAttestationObject,
	AttestationStatementFormat,
	parseClientDataJSON,
	coseAlgorithmES256,
	coseEllipticCurveP256
} from "@oslojs/webauthn";
import { ECDSAPublicKey, p256 } from "@oslojs/crypto/ecdsa";

// Bytes sent from the client
const encodedAttestationObject = new Uint8Array();
const clientDataJSON = new Uint8Array();

const { attestationStatement, authenticatorData } = parseAttestationObject(encodedAttestationObject);
if (attestationStatement.format !== AttestationStatementFormat.None) {
	throw new Error("Invalid attestation statement format");
}
// Use "localhost" for localhost
if (!authenticatorData.verifyRelyingPartyIdHash("example.com")) {
	throw new Error("Invalid relying party ID hash");
}
if (!authenticatorData.userPresent || !authenticatorData.userVerified) {
	throw new Error("User must be present and verified");
}
if (authenticatorData.credential === null) {
	throw new Error("Missing credential");
}
if (authenticatorData.credential.publicKey.algorithm() !== coseAlgorithmES256) {
	throw new Error("Unsupported algorithm");
}

// Parse the COSE key as an EC2 key
// .rsa() for RSA, .okp() for EdDSA, etc
const cosePublicKey = authenticatorData.credential.publicKey.ec2();
if (cosePublicKey.curve !== coseEllipticCurveP256) {
	throw new Error("Unsupported algorithm");
}

const clientData = parseClientDataJSON(clientDataJSON);
if (clientData.type !== ClientDataType.Create) {
	throw new Error("Invalid client data type");
}

if (!verifyChallenge(expectedChallenge)) {
	throw new Error("Invalid challenge");
}
// Use "http://localhost:PORT" for localhost
if (clientData.origin !== "https://example.com") {
	throw new Error("Invalid origin");
}
if (clientData.crossOrigin !== null && clientData.crossOrigin) {
	throw new Error("Invalid origin");
}

// Store the credential ID, algorithm (ES256), and public key with the user's user ID
const credentialId = authenticatorData.credential.id;
const encodedPublicKey = new ECDSAPublicKey(p256, cosePublicKey.x, cosePublicKey.y).encodeSEC1Uncompressed();
```
