---
title: "AuthenticatorData"
---

# AuthenticatorData

The parsed client data.

## Definition

```ts
//$ ClientDataType=/reference/main/ClientDataType
//$ TokenBinding=/reference/main/TokenBinding
interface ClientData {
	type: $$ClientDataType;
	challenge: Uint8Array;
	origin: string;
	crossOrigin: boolean | null;
	tokenBinding: $$TokenBinding | null;
}
```

### Properties

- `type`
- `challenge`
- `origin`
- `crossOrigin`: Can be `null` (not defined in client data JSON)
- `tokenBinding`
