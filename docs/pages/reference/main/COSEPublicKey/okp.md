---
title: "COSEPublicKey.okp()"
---

# COSEPublicKey.okp()

Parses the COSE key as an octet key pair key. Throws an `Error` if fails to parse the key.

This method does not check the `key_ops` parameter.

## Definition

```ts
//$ COSEOKPPublicKey=/reference/main/COSEOKPPublicKey
function okp(): $$COSEOKPPublicKey;
```
