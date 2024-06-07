---
title: "verifyRSASSAPKCS1v1_5Signature()"
---

# verifyRSASSAPKCS1v1_5Signature()

Validates the assertion signature using RSASSA PKCS#1 v1.5.

Supports the following hashing algorithms:

- SHA-1
- SHA-256
- SHA-384
- SHA-512

## Definition

```ts
//$ Hash=/reference/main/Hash
//$ RSAPublicKey=/reference/main/RSAPublicKey
function verifyRSASSAPKCS1v1_5Signature(
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
