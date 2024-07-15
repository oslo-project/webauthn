---
title: "COSEPublicKey.symmetric()"
---

# COSEPublicKey.symmetric()

Parses the COSE key as a symmetric key and returns the key byte array. Throws an `Error` if fails to parse the key.

This method does not check the `key_ops` parameter.

## Definition

```ts
function symmetric(): Uint8Array;
```
