---
title: "Attestation"
---

# Attestation

You can get the attestation statement from `parseAttestationObject()` and parse it to one of the statement formats with `AttestationStatement.packed()`, `AttestationStatement.tpm()`, etc.

```ts
import { parseAttestationObject, AttestationStatementFormat } from "@oslojs/webauthn";
const { attestationStatement, authenticatorData } = parseAttestationObject(encodedAttestationObject);
if (attestationStatement.format !== AttestationStatementFormat.Packed) {
	throw new Error("Invalid attestation statement format");
}
const packed = attestationStatement.packed();
const certificates = packed.certificates;
```
