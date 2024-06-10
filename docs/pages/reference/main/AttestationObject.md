---
title: "AttestationObject"
---

# AttestationObject

The parsed attestation object.

## Definition

```ts
//$ AttestationStatement=/reference/main/AttestationStatement
//$ AuthenticatorData=/reference/main/AuthenticatorData
interface AttestationObject {
	attestationStatement: $$AttestationStatement;
	authenticatorData: $$AuthenticatorData;
}
```

### Properties

- `attestationStatement`
- `authenticatorData`
