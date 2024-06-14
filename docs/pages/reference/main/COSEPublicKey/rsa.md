---
title: "COSEPublicKey.rsa()"
---

# COSEPublicKey.rsa()

Parses the COSE key as an RSA key.

Can throw [`COSEParseError`](/reference/main/COSEParseError). This method does not check the `key_ops` parameter.

## Definition

```ts
//$ COSERSAPublicKey=/reference/main/COSERSAPublicKey
function rsa(): $$COSERSAPublicKey;
```
