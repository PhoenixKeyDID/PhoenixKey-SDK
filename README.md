# @phoenixkeydid/phoenixkey-sdk

Identity & authentication SDK for applications in the **MagicLamp** ecosystem.

Users sign in with **fingerprint or face** on the Aladin App — your app receives a `session_token` and `user_did` without ever touching a private key.

**API Docs:** https://api.phoenixkey.me/docs  
**Full Integration Guide:** https://docs.phoenixkey.me

---

## Installation

This package is published on **GitHub Packages**, not the public npm registry.

### 1. Get a GitHub Personal Access Token

GitHub → Settings → Developer settings → Personal access tokens → Generate new token  
Required scope: `read:packages`

### 2. Configure npm to use the GitHub registry for our scope

Add this to your project's `.npmrc` (or `~/.npmrc` for global):

```
@phoenixkeydid:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${NPM_TOKEN}
```

Then export the token in your shell or CI environment:

```bash
export NPM_TOKEN=ghp_your_token_here
```

### 3. Install

```bash
npm install @phoenixkeydid/phoenixkey-sdk
# or
yarn add @phoenixkeydid/phoenixkey-sdk
# or
pnpm add @phoenixkeydid/phoenixkey-sdk
```

> **Note:** `@microsoft/fetch-event-source` is installed automatically as a dependency.

---

## Quickstart

```typescript
import { PhoenixKeyClient } from "@phoenixkeydid/phoenixkey-sdk";

export const phoenix = new PhoenixKeyClient({
  apiKey:  process.env.NEXT_PUBLIC_PHOENIXKEY_API_KEY!, // From api.phoenixkey.me/docs
  appId:   "my-app",
  appName: "My App",                                    // Shown in Aladin during user approval
});
```

---

## Login Flow

Every login goes through the four steps below. The SDK handles everything — your app only needs to render a QR code and listen for the result.

```
initSession()  →  render QR  →  openStream()  →  receive "approved"
      │                              │
      └── temp_token (auth SSE) ─────┘
```

### Step 1 — Initialize the session

```typescript
const { session_id, temp_token, expires_at } = await phoenix.auth.initSession();

// Generate a QR code from this deep link (use `qrcode` or any equivalent library):
const qrPayload = `aladin://auth?session=${session_id}&app=my-app`;
```

> `temp_token` is only used to authenticate the SSE stream and polling — it is **not** the user's session token.

### Step 2 — Open the SSE stream

SSE is the primary mechanism. The server pushes an event when the user scans their fingerprint on Aladin.

```typescript
const stream = phoenix.auth.openStream(session_id, temp_token, {
  onMessage: ({ data }) => {
    if (data.status === "approved") {
      // Persist the session
      phoenix.session.set(data.session_token, data.user_did);

      // Persist the linked device — next login can skip QR
      if (data.linked_device_token) {
        phoenix.session.setLinkedDevice(data.linked_device_token);
      }

      stream.close();
      router.push("/dashboard");
    }

    if (data.status === "rejected") {
      stream.close();
      showError("User rejected the request");
    }
  },

  // On reconnect, poll once to catch any missed events
  onReconnect: async () => {
    const status = await phoenix.auth.getStatus(session_id, temp_token);
    // Handle the status the same way as onMessage
  },
});

await stream.connect();

// Cleanup on component unmount
onDestroy(() => stream.close());
```

### Step 3 — Handle the `approved` result

```typescript
// data from onMessage when status === "approved":
// {
//   status: "approved",
//   session_token: "eyJhbG...",        // 24h JWT — used for all subsequent API calls
//   user_did: "did:prism:abc...",      // Cardano DID
//   linked_device_token?: "eyJ..."     // 30d JWT — used to skip QR next time
// }
```

---

## Returning Users (Skip QR)

When a `linked_device_token` was saved from a previous login, the app can push a notification directly to Aladin — the user just taps the notification and scans their fingerprint, no need to open the app and scan a QR.

```typescript
if (phoenix.session.hasLinkedDevice()) {
  await phoenix.auth.pushLinkedDevice();
  // Still open the SSE stream to receive the result
  const stream = phoenix.auth.openStream(session_id, temp_token, { /* ... */ });
} else {
  // Show the QR code as usual
}
```

---

## Polling (Fallback)

Use this when SSE is unavailable (some proxies, React Native, etc.):

```typescript
const poll = setInterval(async () => {
  const status = await phoenix.auth.getStatus(session_id, temp_token);

  if (status.status === "approved") {
    clearInterval(poll);
    phoenix.session.set(status.session_token, status.user_did);
  }

  if (status.status === "expired" || status.status === "rejected") {
    clearInterval(poll);
  }
}, 2000); // poll every 2 seconds
```

---

## Checking Login State

```typescript
// Route guard
if (!phoenix.isLoggedIn()) {
  router.push("/login");
}

// Get the current user's DID
const meta = phoenix.session.getSessionMeta();
console.log(meta?.userDid); // "did:prism:abc123..."
```

---

## Logout

```typescript
phoenix.logout(); // Clears session_token + linked_device_token from localStorage
router.push("/login");
```

---

## Error Handling

Every method throws `PhoenixKeyError` on failure.

```typescript
import { PhoenixKeyError } from "@phoenixkeydid/phoenixkey-sdk";

try {
  await phoenix.auth.initSession();
} catch (err) {
  if (err instanceof PhoenixKeyError) {
    console.log(err.status);          // HTTP status (0 = network failure)
    console.log(err.code);            // "session_expired", "invalid_api_key", ...
    console.log(err.userMessageKey);  // "errors.unauthorized", ... (i18n-friendly)
  }
}
```

### Common Error Codes

| `err.code` | `err.status` | Meaning |
|---|---|---|
| `network_error` | `0` | Connection lost |
| `invalid_api_key` | `401` | Invalid API key — check your config |
| `session_not_found` | `404` | `session_id` doesn't exist — create a new session |
| `session_expired` | `410` | QR expired (5 minutes) — create a new session |
| `rate_limited` | `429` | Too many requests — retry after `err.details.retryAfter` seconds |
| `invalid_json` | — | Server response was not valid JSON |

---

## API Reference

### `PhoenixKeyClient`

```typescript
new PhoenixKeyClient(config: PhoenixKeyConfig)
```

| Option | Type | Default | Description |
|---|---|---|---|
| `apiKey` | `string` | *required* | API key from api.phoenixkey.me/docs |
| `appId` | `string` | *required* | Registered app ID |
| `appName` | `string` | *required* | Display name shown in Aladin |
| `apiBaseUrl` | `string` | `https://api.phoenixkey.me` | — |
| `sseBaseUrl` | `string` | `https://api.phoenixkey.me` | — |
| `environment` | `"mainnet" \| "testnet"` | `"mainnet"` | — |

### `client.auth`

| Method | Description |
|---|---|
| `initSession()` | Initialize a login session. Returns `{ session_id, temp_token, challenge, expires_at }` |
| `openStream(sessionId, tempToken, handlers)` | Open an SSE stream. Returns `ResilientSSE` |
| `getStatus(sessionId, tempToken)` | Poll the status once. Returns `LoginSessionStatus` |
| `pushLinkedDevice()` | Send a push notification (requires `hasLinkedDevice() === true`) |

### `client.session`

| Method | Description |
|---|---|
| `set(token, userDid?)` | Store the `session_token` (TTL read from JWT `exp`, default 24h) |
| `getSessionToken()` | Returns the token if valid, `null` otherwise |
| `getSessionMeta()` | Returns `{ expiresAt, userDid }` |
| `clearSession()` | Removes the session token |
| `setLinkedDevice(token)` | Stores the `linked_device_token` (30d TTL) |
| `hasLinkedDevice()` | `true` if a valid linked device exists |
| `clearLinkedDevice()` | Removes the linked device token |
| `isLoggedIn()` | Shortcut: `getSessionToken() !== null` |
| `clearAll()` | Clears both session and linked device |

### `client.isLoggedIn()`

Shortcut for `client.session.isLoggedIn()`.

### `client.logout()`

Calls `clearAll()` — clears all PhoenixKey data from localStorage.

---

## Backend Endpoints (Reference)

Full documentation at **https://api.phoenixkey.me/docs**

| Method | Path | Required Auth Headers |
|---|---|---|
| `POST` | `/auth/session/init` | `x-api-key` |
| `GET` | `/auth/session/{id}/status` | `x-api-key` + `Authorization: Bearer <temp_token>` |
| `GET` | `/auth/session/{id}/stream` | `x-api-key` + `Authorization: Bearer <temp_token>` |
| `POST` | `/auth/session/push` | `x-api-key` + `Authorization: Bearer <linked_device_token>` |

> **Note:** The SDK automatically attaches `x-api-key` to every request. You don't need to set this header manually.

---

## Full Example

See [`examples/nextjs/login-page.tsx`](./examples/nextjs/login-page.tsx) for a complete Next.js 14 App Router example.

---

## Related Repositories

- **PhoenixKey Core:** `github.com/PhoenixKeyDID/PhoenixKey` — DID registry, smart contracts, Enclave
- **PhoenixKey API:** `github.com/PhoenixKeyDID/PhoenixKey` → `apps/api/`
- **PhoenixKey Database:** `github.com/PhoenixKeyDID/PhoenixKey-Database`
- **Full Documentation:** https://docs.phoenixkey.me

---

## License

MIT © 2026 MagicLamp Network

---

## Aladin App (Required for Users)

End users need the **Aladin App** installed to scan the QR codes your application displays. The app holds the user's keys in the device's Secure Enclave / TEE and signs all approval requests with biometrics.

| Platform | Link |
|---|---|
| Android | [Google Play](https://play.google.com/store/apps/details?id=com.aladincontract.company) |
| iOS | [App Store](https://apps.apple.com/app/id6737107665) |

> Make sure your login UI links users to one of these stores when they don't have Aladin installed yet — for example, below the QR code: *"Don't have Aladin? Download for [Android](https://play.google.com/store/apps/details?id=com.aladincontract.company) or [iOS](https://apps.apple.com/app/id6737107665)."*
