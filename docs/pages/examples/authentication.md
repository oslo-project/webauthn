---
title: "Authentication"
---

# Authentication

See the [WebAuthn guide](https://thecopenhagenbook.com/webauthn) in the Copenhagen Book for details on WebAuthn.

Call `navigator.credentials.get()` to authenticate the user with a credential on their device and send the returned credential ID, signature, authenticator data, and client data JSON to the server.

```ts
import { encodeBase64 } from "@oslojs/encoding";

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
		credentialId: encodeBase64(new Uint8Array(credential.rawId)),
		signature: encodeBase64(new Uint8Array(credential.response.signature)),
		authenticatorData: encodeBase64(new Uint8Array(credential.response.authenticatorData)),
		clientDataJSON: encodeBase64(new Uint8Array(credential.response.clientDataJSON))
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
import { decodeSEC1PublicKey, decodePKIXECDSASignature, p256, verifyECDSASignature } from "@oslojs/crypto/ecdsa";
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
const ecdsaSignature = decodePKIXECDSASignature(signature);
const ecdsaPublicKey = decodeSEC1PublicKey(p256, credential.encodedPublicKey);
const hash = sha256(createAssertionSignatureMessage(encodedAuthenticatorData, clientDataJSON));
const valid = verifyECDSASignature(ecdsaPublicKey, hash, ecdsaSignature);
if (valid) {
	const userId = credential.userId;
	// ...
}
```
