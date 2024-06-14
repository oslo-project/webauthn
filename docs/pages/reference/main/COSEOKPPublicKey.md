---
title: "COSEOKPPublicKey"
---

# COSEOKPPublicKey

Represents a COSE octet key pair (OKP) public key for EdDSA as defined in [RFC 9053](https://www.rfc-editor.org/rfc/rfc9053.html#name-elliptic-curve-keys).

## Definition

```ts
//$ COSEEllipticCurve=/reference/main/COSEEllipticCurve
interface ECDSAPublicKey {
	curve: $$COSEEllipticCurve;
	x: Uint8Array;
}
```

### Properties

- `curve`
- `x`
