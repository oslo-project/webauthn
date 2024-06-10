---
title: "createSignatureMessage()"
---

# createSignatureMessage()

Creates the message to verify the assertion signature against.

## Definition

```ts
function createSignatureMessage(authenticatorData: Uint8Array, clientDataJSON: Uint8Array): Uint8Array;
```

### Parameters

- `authenticatorData`
- `clientDataJSON`
