---
title: "TPMAttestationStatement"
---

# TPMAttestationStatement

See [TPM Attestation Statement Format](https://www.w3.org/TR/webauthn-2/#sctn-tpm-attestation).

## Definition

```ts
//$ COSEAlgorithm=/reference/main/COSEAlgorithm
interface TPMAttestationStatement {
	algorithm: $$COSEAlgorithm;
	signature: Uint8Array;
	certificates: Uint8Array[];
	attestation: Uint8Array;
	publicKey: Uint8Array;
}
```

### Properties

- `algorithm`
- `signature`
- `certificates`: A series of X.509 encoded certificates, where the first one is the AIK certificate and the rest is its certificate chain.
- `attestation`: The `TPMS_ATTEST` structure
- `publicKey`: The `TPMT_PUBLIC` structure
