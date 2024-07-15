---
title: "COSEPublicKey"
---

# COSEPublicKey

Represents a COSE pubic key.

This is not intended to be constructed directly.

## Constructor

```ts
function constructor(decoded: object): this;
```

### Parameters

- `decoded`

## Methods

- [`COSEPublicKey.algorithm()`](/reference/main/COSEPublicKey/algorithm)
- [`COSEPublicKey.isAlgorithmDefined()`](/reference/main/COSEPublicKey/isAlgorithmDefined)
- [`COSEPublicKey.ec2()`](/reference/main/COSEPublicKey/ec2)
- [`COSEPublicKey.okp()`](/reference/main/COSEPublicKey/okp)
- [`COSEPublicKey.rsa()`](/reference/main/COSEPublicKey/rsa)
- [`COSEPublicKey.symmetric()`](/reference/main/COSEPublicKey/symmetric)
- [`COSEPublicKey.type()`](/reference/main/COSEPublicKey/type)

## Properties

```ts
interface Properties {
	decoded: object;
}
```

- `decoded`
