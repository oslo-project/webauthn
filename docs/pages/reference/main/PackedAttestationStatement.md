---
title: "PackedAttestationStatement"
---

# PackedAttestationStatement

See [Packed Attestation Statement Format](https://www.w3.org/TR/webauthn-2/#sctn-packed-attestation).

## Definition

```ts
//$ COSEAlgorithm=/reference/main/COSEAlgorithm
interface PackedAttestationStatement {
	algorithm: $$COSEAlgorithm;
	signature: Uint8Array;
	certificates: Uint8Array[] | null;
}
```

### Properties

- `algorithm`
- `signature`
- `certificates`: If defined, a series of X.509 encoded certificates, where the first one is the attestation certificate and the rest is its certificate chain.
