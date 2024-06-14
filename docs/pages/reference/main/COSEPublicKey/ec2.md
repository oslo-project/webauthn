---
title: "COSEPublicKey.ec2()"
---

# COSEPublicKey.ec2()

Parses the COSE key as an elliptic curve (EC2) key. This only supports keys where both the x and y coordinates are defined.

Can throw [`COSEParseError`](/reference/main/COSEParseError). This method does not check the `key_ops` parameter.

## Definition

```ts
//$ COSEEC2PublicKey=/reference/main/COSEEC2PublicKey
function ec2(): $$COSEEC2PublicKey;
```
