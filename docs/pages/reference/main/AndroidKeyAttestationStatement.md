---
title: "AndroidKeyAttestationStatement"
---

# AndroidKeyAttestationStatement

See [Android Key Attestation Statement Format](https://www.w3.org/TR/webauthn-2/#sctn-android-key-attestation).

## Definition

```ts
//$ COSEAlgorithm=/reference/main/COSEAlgorithm
interface AndroidKeyAttestationStatement {
	algorithm: $$COSEAlgorithm;
	signature: Uint8Array;
	certificates: Uint8Array[];
}
```

### Properties

- `algorithm`
- `signature`
- `certificates`: A series of ASN.1 DER encoded certificates.
