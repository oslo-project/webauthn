---
title: "COSEPublicKey.algorithm()"
---

# COSEPublicKey.algorithm()

Returns the algorithm of the COSE key using the `alg` parameter. Throws [`COSEParseError`](/reference/main/COSEParseError) if the `alg` parameter is undefined, is the wrong type, or is not registered on IANA.

## Definition

```ts
//$ COSEAlgorithm=/reference/main/COSEAlgorithm
function algorithm(): $$COSEAlgorithm;
```
