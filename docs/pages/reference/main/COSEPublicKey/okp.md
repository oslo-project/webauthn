---
title: "COSEPublicKey.okp()"
---

# COSEPublicKey.okp()

Parses the COSE key as an octet key pair key.

Can throw [`COSEParseError`](/reference/main/COSEParseError). This method does not check the `key_ops` parameter.

## Definition

```ts
//$ COSEOKPPublicKey=/reference/main/COSEOKPPublicKey
function okp(): $$COSEOKPPublicKey;
```
