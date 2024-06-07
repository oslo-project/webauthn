---
title: "AppleAnonymousAttestationStatement"
---

# AppleAnonymousAttestationStatement

See [Apple Anonymous Attestation Statement Format](https://www.w3.org/TR/webauthn-2/#sctn-apple-anonymous-attestation).

## Definition

```ts
//$ COSEAlgorithm=/reference/main/COSEAlgorithm
interface AppleAnonymousAttestationStatement {
	certificates: Uint8Array[];
}
```

### Properties

- `certificates`: A series of X.509 encoded certificates, where the first one is the attestation certificate and the rest is its certificate chain.
