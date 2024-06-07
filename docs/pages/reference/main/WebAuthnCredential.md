---
title: "WebAuthnCredential"
---

# WebAuthnCredential

## Definition

```ts
//$ COSEPublicKey=/reference/main/COSEPublicKey
interface WebAuthnCredential {
	authenticatorAAGUID: Uint8Array;
	id: Uint8Array;
	publicKey: $$COSEPublicKey;
}
```

### Properties

- `authenticatorAAGUID`
- `id`
- `publicKey`
