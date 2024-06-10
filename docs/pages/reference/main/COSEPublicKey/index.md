---
title: "COSEPublicKey"
---

# COSEPublicKey

Represents a COSE pubic key.

## Constructor

```ts
//$ DecodedCOSEPublicKey=/reference/main/DecodedCOSEPublicKey
function constructor(decoded: $$DecodedCOSEPublicKey): this;
```

### Parameters

- `decoded`: See [`DecodedCOSEPublicKey`](/reference/main/DecodedCOSEPublicKey) for decoding rules.

## Methods

- [`COSEPublicKey.algorithm()`](/reference/main/COSEPublicKey/algorithm)
- [`COSEPublicKey.ecdsa()`](/reference/main/COSEPublicKey/ecdsa)
- [`COSEPublicKey.rsa()`](/reference/main/COSEPublicKey/rsa)

## Properties

```ts
//$ DecodedCOSEPublicKey=/reference/main/DecodedCOSEPublicKey
interface Properties {
	decoded: $$DecodedCOSEPublicKey;
}
```

- `decoded`
