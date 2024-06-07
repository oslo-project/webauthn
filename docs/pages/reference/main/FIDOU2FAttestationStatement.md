---
title: "FIDOU2FAttestationStatement"
---

# FIDOU2FAttestationStatement

See [FIDO U2F Attestation Statement Format](https://www.w3.org/TR/webauthn-2/#sctn-fido-u2f-attestation).

## Definition

```ts
interface FIDOU2FAttestationStatement {
	signature: Uint8Array;
	certificate: Uint8Array;
}
```

### Properties

- `signature`
- `certificate`
