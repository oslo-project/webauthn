# @oslojs/webauthn

**Documentation: https://webauthn.oslojs.dev**

> [!CAUTION] **This package is highly experimental!**

A JavaScript library for working with the Web Authentication API on the server by [Oslo](https://oslojs.dev).

- Runtime-agnostic
- No third-party dependencies
- Fully typed

```ts
import { parseAttestationObject, COSEKeyType, COSEAlgorithm } from "@oslojs/webauthn";
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
if (authenticatorData.credential.publicKey.type() !== COSEKeyType.EC2) {
	throw new Error("Unsupported algorithm");
}
if (authenticatorData.credential.publicKey.algorithm() !== COSEAlgorithm.ES256) {
	throw new Error("Unsupported algorithm");
}
const publicKey = authenticatorData.credential.publicKey.ec2();
```

This package currently does not support attestation extensions and also does not provide APIs for verifying attestation statements (e.g FIDO-U2F, TPM).

## Installation

```
npm i @oslojs/webauthn
```
