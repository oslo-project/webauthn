---
title: "AndroidKeyAttestationStatement"
---

# AndroidKeyAttestationStatement

See [Android Key Attestation Statement Format](https://www.w3.org/TR/webauthn-2/#sctn-android-key-attestation).

## Definition

```ts
interface AndroidKeyAttestationStatement {
	algorithm: number;
	signature: Uint8Array;
	certificates: Uint8Array[];
}
```

### Properties

- `algorithm`: IANA COSE algorithm ID
- `signature`
- `certificates`: A series of ASN.1 DER encoded certificates.
