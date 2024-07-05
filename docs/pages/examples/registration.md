---
title: "Registration"
---

# Registration

First generate a random challenge on the server, anywhere from 16 to 32 bytes. This should be stored on the server and be single use. We recommend tying the challenge to the current session or providing the client with an "attempt ID" that it can send to the server.

Use `navigator.credentials.create()` to create a new credential on the device. For using passkeys as the main authentication method, `attestation` should be `none` and `userVerification` should be `required`. `userVerification` can be `preferred` if you're using passkeys as a second-factor on top of passwords. Most, if not all devices, support ES256 (ECDSA with P-256 and SHA-256), identified with `-7`.

Send the attestation object and client data JSON to the server.

```ts
import { base64 } from "@oslojs/encoding";

// Random bytes generated in the server.
// This must be generated on each attempt.
const challenge = new Uint8Array(20);

// random ID for the authenticator
// this does not need to match the actual user ID
const userId = new Uint8Array(20);
crypto.getRandomValues(userId);

const credential = await navigator.credentials.create({
	publicKey: {
		challenge,
		user: {
			displayName: "User",
			id: userId,
			name: "user@example.com" // user identifier like username or email
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
		attestation: "none", // none for passkeys
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
	// this example uses JSON but you can use something like CBOR to get something more compact
	body: JSON.stringify({
		attestationObject: base64.encode(new Uint8Array(credential.response.attestationObject)),
		clientDataJSON: base64.encode(new Uint8Array(credential.response.clientDataJSON))
	})
});
```

On the server, parse the attestation object and client data JSON. For the attestation object, verify the attestation statement format, relying party ID hash, user present and user verified flags, and the algorithm used. For the client data JSON, check the challenge and origin. If all checks passes, store the credential ID, algorithm, and public key alongside the user ID.

We recommend using [`@oslojs/crypto`](https://crypto.oslojs.dev) for handling ECDSA public keys and signatures.

```ts
import { parseAttestationObject, AttestationStatementFormat, parseClientDataJSON } from "@oslojs/webauthn";
import { ECDSAPublicKey, p256 } from "@oslojs/crypto/ecdsa";
import { compareBytes } from "@oslojs/binary";

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
if (authenticatorData.credential.publicKey.algorithm() !== COSEAlgorithm.ES256) {
	throw new Error("Unsupported algorithm");
}

// Parse the COSE key as an EC2 key
// .rsa() for RSA, .okp() for EdDSA, etc
const cosePublicKey = authenticatorData.credential.publicKey.ec2();
if (cosePublicKey.curve !== COSEEllipticCurve.P256) {
	throw new Error("Unsupported algorithm");
}

const clientData = parseClientDataJSON(clientDataJSON);
if (clientData.type !== ClientDataType.Create) {
	throw new Error("Invalid client data type");
}

// Verify that the challenge is valid.
const expectedChallenge = getChallenge(); // make sure to delete the challenge after use
if ((!compareBytes(clientData.challenge), expectedChallenge)) {
	throw new Error("Invalid challenge");
}
// Use "http://localhost:5000" for localhost
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
