---
title: "AttestationStatement"
---

# AttestationStatement

Represents an attestation statement.

The `decoded` parameter is a CBOR-decoded object where:

- COSE integers are `Number`
- COSE bit strings are `Uint8Array`
- COSE arrays are JS arrays
- COSE maps are JS objects with stringified keys

## Constructor

```ts
//$ AttestationStatementFormat=/reference/main/AttestationStatementFormat
function constructor(format: $$AttestationStatementFormat, decoded: object): this;
```

### Parameters

- `format`
- `decoded`

## Methods

- [`AttestationStatement.androidKey()`](/reference/main/AttestationStatement/androidKey)
- [`AttestationStatement.androidSafetyNet()`](/reference/main/AttestationStatement/androidSafetyNet)
- [`AttestationStatement.appleAnonymous()`](/reference/main/AttestationStatement/appleAnonymous)
- [`AttestationStatement.fidoU2F()`](/reference/main/AttestationStatement/fidoU2F)
- [`AttestationStatement.packed()`](/reference/main/AttestationStatement/packed)
- [`AttestationStatement.tpm()`](/reference/main/AttestationStatement/tpm)

## Properties

```ts
//$ AttestationStatementFormat=/reference/main/AttestationStatementFormat
interface Properties {
	format: $$AttestationStatementFormat;
	decoded: object;
}
```

- `format`
- `decoded`
