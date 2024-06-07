---
title: "parseClientDataJSON()"
---

# parseAuthenticatorData()

Parses the authenticator data.

Can throw [`ClientDataParseError](/reference/main/AuthenticatorDataParseError).

## Definition

```ts
//$ ClientData=/reference/main/ClientData
function parseClientDataJSON(encoded: Uint8Array): $$ClientData;
```

### Parameters

- `encoded`: Encoded client data JSON
