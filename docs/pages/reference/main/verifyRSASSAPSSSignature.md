---
title: "verifyRSASSAPSSSignature()"
---

# verifyRSASSAPSSSignature()

Validates the assertion signature using RSASSA PSS.

Supports the following hashing algorithms:

- SHA-1
- SHA-256
- SHA-384
- SHA-512

## Definition

```ts
//$ Hash=/reference/main/Hash
//$ RSAPublicKey=/reference/main/RSAPublicKey
function verifyRSASSAPSSSignature(
	hash: $$Hash,
	publicKey: $$RSAPublicKey,
	signature: Uint8Array,
	authenticatorData: Uint8Array,
	clientDataJSON: Uint8Array
):
```

### Parameters

- `hash`
- `publicKey`
- `signature`
- `authenticatorData`: Encoded authenticator data
- `clientDataJSON`: Encoded client data JSON
