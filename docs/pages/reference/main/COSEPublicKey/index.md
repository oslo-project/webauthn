---
title: "COSEPublicKey"
---

# COSEPublicKey

Represents a COSE pubic key.

This takes the decoded COSE public key, where:

- COSE integers are `Number`
- COSE bit strings are `Uint8Array`
- COSE arrays are JS arrays
- COSE maps are JS objects with stringified keys

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

## Properties

```ts
interface Properties {
	decoded: object;
}
```

- `decoded`

## Example

```ts
import { COSEPublicKey } from "@oslojs/webauthn";

const decoded = {
	1: 2,
	3: -7,
	"-1": 1,
	"-2": new Uint8Array([...new Uint8Array(29), 0x00, 0x01, 0x00]),
	"-3": new Uint8Array([...new Uint8Array(29), 0x01, 0x00, 0x00])
};

const coseKey = new COSEPublicKey();
if (coseKey.isAlgorithmDefined() && coseKey.algorithm() !== COSEAlgorithm.ES256) {
	throw new Error("Unsupported algorithm");
}
if (coseKey.keyType() !== COSEAlgorithm.ES256) {
	throw new Error("Invalid key type");
}
const ec2Key = coseKey.ec2();
```
