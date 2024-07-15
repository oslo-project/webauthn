---
title: "AndroidSafetyNetAttestationStatement"
---

# AndroidSafetyNetAttestationStatement

See [Android SafetyNet Attestation Statement Format](https://www.w3.org/TR/webauthn-2/#sctn-android-safetynet-attestation).

## Definition

```ts
interface AndroidSafetyNetAttestationStatement {
	version: string;
	response: Uint8Array;
}
```

### Properties

- `version`
- `response`
