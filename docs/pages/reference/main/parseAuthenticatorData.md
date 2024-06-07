---
title: "parseAuthenticatorData()"
---

# parseAuthenticatorData()

Parses the authenticator data.

Can throw [`AuthenticatorDataParseError](/reference/main/AuthenticatorDataParseError).

## Definition

```ts
//$ AuthenticatorData=/reference/main/AuthenticatorData
function parseAuthenticatorData(encoded: Uint8Array): $$AuthenticatorData;
```

### Parameters

- `encoded`: Encoded authenticator data
