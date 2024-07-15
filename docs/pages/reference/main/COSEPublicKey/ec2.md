---
title: "COSEPublicKey.ec2()"
---

# COSEPublicKey.ec2()

Parses the COSE key as an elliptic curve (EC2) key. Throws an `Error` if fails to parse the key. This only supports keys where both the x and y coordinates are defined.

This method does not check the `key_ops` parameter.

## Definition

```ts
//$ COSEEC2PublicKey=/reference/main/COSEEC2PublicKey
function ec2(): $$COSEEC2PublicKey;
```
