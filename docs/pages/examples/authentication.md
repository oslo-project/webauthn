---
title: "Authentication"
---

# Authentication

Generate a random challenge on the server and call `navigator.credentials.get()` to authenticate the user with a credential on their device.

Send the credential ID, signature, authenticator data, and client data JSON to the server.

```ts
import { base64 } from "@oslojs/encoding";

// Random bytes generated in the server.
// This must be generated on each attempt.
const challenge = new Uint8Array(20);

// random ID for the authenticator
// this does not need to match the actual user ID
const userId = new Uint8Array(20);
crypto.getRandomValues(userId);

const credential = await await navigator.credentials.get({
	publicKey: {
		challenge,
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
		authenticatorData: base64.encode(new Uint8Array(credential.response.authenticatorData)),
		clientDataJSON: base64.encode(new Uint8Array(credential.response.clientDataJSON))
	})
});
```

On the server, parse the authenticator data and client data JSON. For the authenticator data, relying party ID hash, and the user present and user verified flags. For the client data JSON, check the challenge and origin. If all checks passes, verify the signature against `createAssertionSignatureMessage()` using the public key of the credential.

We recommend using [`@oslojs/crypto`](https://crypto.oslojs.dev) for handling ECDSA public keys and signatures. `verifyECDSASignature()` is not fully constant-time but it's fine here since the message and key is public. For ECDSA, signatures are ASN.1 DER encoded.

```ts
import {
	parseAuthenticatorData,
	AttestationStatementFormat,
	parseClientDataJSON,
	createAssertionSignatureMessage
} from "@oslojs/webauthn";
import { decodeSEC1PublicKey, decodeX509ECDSASignature, p256, verifyECDSASignature } from "@oslojs/crypto/ecdsa";
import { compareBytes } from "@oslojs/binary";
import { sha256 } from "@oslojs/crypto/sha2";

// Bytes sent from the client
const credentialId = new Uint8Array();
const signature = new Uint8Array();
const encodedAuthenticatorData = new Uint8Array();
const clientDataJSON = new Uint8Array();

const authenticatorData = parseAuthenticatorData(encodedAuthenticatorData);
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

// Get public key and user ID from credential ID
const credential = getCredential(credentialId);
// Decode DER-encoded signature
const ecdsaSignature = decodeX509ECDSASignature(signature);
const ecdsaPublicKey = decodeSEC1PublicKey(p256, credential.encodedPublicKey);
const hash = sha256(createAssertionSignatureMessage(authenticatorData, clientDataJSON));
const valid = verifyECDSASignature(ecdsaPublicKey, hash, ecdsaSignature);
if (valid) {
	const userId = credential.userId;
	// ...
}
```
