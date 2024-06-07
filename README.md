# @oslojs/webauthn

**This package is highly experimental!**

**Documentation: https://webauthn.oslojs.dev**

A JavaScript library for working with the Web Authentication API on the server by [Oslo](https://oslojs.dev).

- Runtime-agnostic
- No third-party dependencies
- Fully typed

```ts
import { parseAttestationObject, COSEAlgorithm } from "@oslojs/webauthn";
import { sha256 } from "@oslojs/crypto";
import { compareBytes } from "@oslojs/binary";

const { attestationStatement, authenticatorData } = await parseAttestationObject(encoded);
if (!authenticatorData.userPresent || !authenticatorData.userVerified) {
	throw new Error("User must be verified");
}
const relyingPartyIdHash = sha256("localhost");
if (!compareBytes(authenticatorData.relyingPartyIdHash, relyingPartyIdHash)) {
	throw new Error("Invalid relying party ID hash");
}
if (authenticatorData.credential === null) {
	throw new Error("Expected credential");
}
if (authenticatorData.credential.publicKey.algorithm !== COSEAlgorithm.ES256) {
	throw new Error("Unsupported algorithm");
}
const publicKey = authenticatorData.credential.publicKey.algorithm.ecdsa();
```

This package currently does not support attestation extensions and also does not provide APIs for verifying attestation statements (e.g FIDO-U2F, TPM).

## Installation

```
npm i @oslojs/webauthn
```

## Prerequisites

This package requires the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API). This is available in most modern runtimes, including Node.js 20+, Deno, Bun, and Cloudflare Workers. The big exception is Node.js 16 and 18. Make sure to polyfill it using `webcrypto`.

```ts
import { webcrypto } from "node:crypto";

globalThis.crypto = webcrypto;
```

Alternatively, add the `--experimental-global-webcrypto` flag when executing files.

```
node --experimental-global-webcrypto index.js
```
