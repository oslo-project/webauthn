---
title: "DecodedCOSEPublicKey"
---

# DecodedCOSEPublicKey

The decoded COSE public key, where:

- COSE integers are `Number`
- COSE bit strings are `Uint8Array`
- COSE arrays are JS arrays
- COSE maps are JS objects with stringified keys

## Definition

```ts
interface DecodedCOSEPublicKey {
	1: number;
	3: number;
}
```

### Properties

- `1`
- `3`
