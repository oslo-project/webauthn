---
title: "Authentication"
---

# Authentication

Generate a random challenge on the server and call `navigator.credentials.get()` to authenticate the user with a credential on their device.

Send the credential ID, signature, attestation object, and client data JSON to the server.

```ts
import { base64 } from "@oslojs/encoding";

// Random bytes generated in the server.
// This must be generated on each attempt.
const challenge = new Uint8Array(20);

// random ID for the authenticator
// this does not need to match the actual user ID
const userId = new Uint8Array(20);
crypto.randomValues(userId);

const credential = await await navigator.credentials.get({
	publicKey: {
		challenge,
		attestation: "none",
		userVerification: "required"
	}
});

if (!(credential instanceof PublicKeyCredential)) {
	throw new Error("Failed to create public key");
}
if (!(credential.response instanceof AuthenticatorAssertionResponse)) {
	throw new Error("Unexpected error");
}

const response = await fetch("/api/register", {
	method: "POST",
	// this example uses JSON but you can use something like CBOR to get something more compact
	body: JSON.stringify({
		credentialId: base64.encode(new Uint8Array(credential.rawId)),
		signature: base64.encode(new Uint8Array(credential.response.signature)),
		attestationObject: base64.encode(new Uint8Array(credential.response.attestationObject)),
		clientDataJSON: base64.encode(new Uint8Array(credential.response.clientDataJSON))
	})
});
```

On the server, parse the attestation object and client data JSON. For the attestation object, verify the attestation statement format, relying party ID hash, and the user present and user verified flags. For the client data JSON, check the challenge and origin. If all checks passes, verify the signature against `createAssertionSignatureMessage()` using the public key of the credential.

We recommend using [`@oslojs/crypto`](https://crypto.oslojs.dev) for handling ECDSA public keys and signatures. `verifyECDSA()` is not fully constant-time, though it's fine for most cases since it doesn't use any secrets (e.g. private key).

For ECDSA, signatures are ASN.1 DER encoded. We recommend using [`@oslojs/asn1`](https://asn1.oslojs.dev) for decoding.

```ts
import {
	parseAttestationObject,
	AttestationStatementFormat,
	parseClientDataJSON,
	createAssertionSignatureMessage
} from "@oslojs/webauthn";
import { decodeSEC1PublicKey, p256, verifyECDSA } from "@oslojs/crypto/ecdsa";
import { compareBytes } from "@oslojs/binary";
import { sha256 } from "@oslojs/crypto/sha2";
import { parseASN1NoLeftoverBytes } from "@oslojs/asn1";

// Bytes sent from the client
const credentialId = new Uint8Array();
const signature = new Uint8Array();
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

const clientData = parseClientDataJSON(clientDataJSON);
if (clientData.type !== ClientDataType.Get) {
	throw new Error("Invalid client data type");
}

// Verify that the challenge
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

// Get public key and user ID from credential ID
const credential = getCredential(credentialId);
// Decode DER-encoded signature
const signatureSequence = parseASN1NoLeftoverBytes(signature).sequence();
const r = signatureSequence.at(0).integer().value;
const s = signatureSequence.at(1).integer().value;
const ecdsaPublicKey = decodeSEC1PublicKey(credential.encodedPublicKey);
const hash = sha256(createAssertionSignatureMessage(authenticatorData, clientDataJSON));
const valid = verifyECDSA(ecdsaPublicKey, hash, r, s);
if (valid) {
	const userId = credential.userId;
	// ...
}
```
