---
title: "parseAttestationObject()"
---

# parseAttestationObject()

Parses the attestation object.

Can throw [`AttestationObjectParseError`](/reference/main/AttestationObjectParseError) and [`AuthenticatorDataParseError](/reference/main/AuthenticatorDataParseError).

## Definition

```ts
//$ AttestationObject=/reference/main/AttestationObject
function parseAttestationObject(encoded: Uint8Array): $$AttestationObject;
```

### Parameters

- `encoded`: Encoded attestation object
