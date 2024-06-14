---
title: "COSEPublicKey.symmetric()"
---

# COSEPublicKey.symmetric()

Parses the COSE key as a symmetric key and returns the key byte array.

Can throw [`COSEParseError`](/reference/main/COSEParseError). This method does not check the `key_ops` parameter.

## Definition

```ts
function symmetric(): Uint8Array;
```
