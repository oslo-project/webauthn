---
title: "verifyECDSASignature()"
---

# verifyECDSASignature()

Validates the assertion signature using ECDSA.

Supports the following hashing algorithms:

- SHA-1
- SHA-256
- SHA-384
- SHA-512

and the following curves:

- P-256
- P-384
- P-512

## Definition

```ts
//$ Hash=/reference/main/Hash
//$ ECDSAPublicKey=/reference/main/ECDSAPublicKey
function verifyECDSASignature(
	hash: $$Hash,
	publicKey: $$ECDSAPublicKey,
	derSignature: Uint8Array,
	authenticatorData: Uint8Array,
	clientDataJSON: Uint8Array
): Promise<boolean>;
```

### Parameters

- `hash`
- `publicKey`
- `derSignature`: ASN.1 DER encoded signature passed by the client.
- `authenticatorData`: Encoded authenticator data
- `clientDataJSON`: Encoded client data JSON
