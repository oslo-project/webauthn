---
title: "AuthenticatorData"
---

# AuthenticatorData

The parsed authenticator data.

## Constructor

```ts
//$ AuthenticatorDataFlags=/reference/main/AuthenticatorDataFlags
//$ WebAuthnCredential=/reference/main/WebAuthnCredential
function constructor(
	relyingPartyIdHash: Uint8Array,
	flags: $$AuthenticatorDataFlags,
	signatureCounter: number,
	credential: $$WebAuthnCredential | null,
	extensions: null
): this;
```

## Methods

- [`verifyRelyingPartyIdHash()`](/reference/main/AuthenticatorData/verifyRelyingPartyIdHash)

## Properties

```ts
//$ WebAuthnCredential=/reference/main/WebAuthnCredential
interface Properties {
	relyingPartyIdHash: Uint8Array;
	userPresent: boolean;
	userVerified: boolean;
	signatureCounter: number;
	credential: $$WebAuthnCredential | null;
	extensions: null;
}
```

- `relyingPartyIdHash`: The [relying party ID](https://www.w3.org/TR/webauthn-2/#relying-party-identifier)
- `userPresent`: The [user present](https://www.w3.org/TR/webauthn-2/#concept-user-present) flag
- `userVerified`: The [user verified](https://www.w3.org/TR/webauthn-2/#concept-user-verified) flag
- `signatureCounter`
- `credential`: Only defined during attestation
- `extensions`: Currently unsupported
