---
title: "COSEEC2PublicKey"
---

# COSEEC2PublicKey

Represents a COSE elliptic curve (EC2) public key for ECDSA as defined in [RFC 9053](https://www.rfc-editor.org/rfc/rfc9053.html#name-elliptic-curve-keys).

This can only represent keys where both the x and y coordinates are defined.

## Definition

```ts
interface COSEEC2PublicKey {
	curve: number;
	x: bigint;
	y: bigint;
}
```

### Properties

- `curve`: IANA COSE elliptic curve ID.
- `x`
- `y`
