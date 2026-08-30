# @phoenixkeydid/phoenixkey-sdk

Identity & auth SDK for the **MagicLamp / Aladin** ecosystem. Sign in with **fingerprint or face** on the Aladin app — your app receives `session_token` + `user_did` without ever touching a private key.

---

## Install

```bash
# .npmrc
@phoenixkeydid:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${NPM_TOKEN}
```

```bash
export NPM_TOKEN=ghp_xxx     # GitHub PAT, scope read:packages
npm install @phoenixkeydid/phoenixkey-sdk qrcode
```

---

## Step 1 — Initialize client

```ts
import { PhoenixKeyClient } from "@phoenixkeydid/phoenixkey-sdk";

export const phoenix = new PhoenixKeyClient({
  appId: "orilife-web-v1", // unique within Aladin ecosystem
  appName: "OriLife", // shown in mobile approval screen
  domain: "orilife.com", // bound into auth challenge — anti-phishing
  environment: "mainnet", // or "preprod"
});
```

---

## Step 2 — Login flow (login page)

```ts
import QRCode from "qrcode";

const init = await phoenix.auth.initSession();

// Render QR
await QRCode.toCanvas(canvasEl, phoenix.auth.buildQrPayload(init), {
  width: 256,
});

// Listen for mobile approval
const stream = phoenix.auth.openStream(init.session_id, init.temp_token, {
  onMessage: ({ type, data }) => {
    if (type === "approved" && data.status === "approved") {
      phoenix.session.setSession(data.session_token!, data.user_did);
      if (data.linked_device_token) {
        phoenix.session.setLinkedDevice(data.linked_device_token);
      }
      stream.close();
      router.push("/dashboard");
    }
  },
  onReconnect: async () => {
    // Catch missed events after SSE reconnect
    const s = await phoenix.auth.getStatus(init.session_id, init.temp_token);
    if (s.status === "approved") stream.close();
  },
});
await stream.connect();
```

**Skip QR on return visits** (when user has previously logged in):

```ts
if (phoenix.session.hasLinkedDevice()) {
  await phoenix.auth.pushLinkedDevice(init.session_id);
  // Show "check your phone" UI, fall back to QR after ~8s
}
```

---

## Step 3 — Request a signature (after login)

When your app needs the user to authorize an action (transfer, settings change, etc.):

```ts
const sessionId = currentLoginSessionId; // from Step 2

const intent = phoenix.signRequest.buildIntent({
  type: "TRANSFER",
  body: { amount: "100 LAMP", to: "addr1q..." },
  display_text: "Transfer 100 LAMP to shop", // user sees this on phone
});

const stream = phoenix.signRequest.openStream(sessionId, sessionToken, {
  onMessage: ({ type, data }) => {
    if (type === "signed" && data.status === "approved") {
      // Forward to your backend → verify with verifier SDK (Step 4)
      submitToBackend({
        intent,
        signature: data.signature,
        public_key_hex: data.public_key_hex,
        user_did: phoenix.session.getSessionMeta()?.userDid,
      });
    }
    if (type === "cancelled") showToast("Signing cancelled");
  },
});
await stream.connect();

await phoenix.signRequest.create(sessionId, intent);
```

---

## Step 4 — Verify on your backend

Verify signatures locally — no PhoenixKey server roundtrip per request.

```ts
import { PhoenixKeyVerifier } from "@phoenixkeydid/phoenixkey-sdk/verifier";

const verifier = new PhoenixKeyVerifier();

// In your route handler
app.post("/orilife/transfer", async (req, res) => {
  const { user_did, intent, signature } = req.body;

  const result = await verifier.verifyIntent({ user_did, intent, signature });
  if (!result.valid) {
    return res.status(403).json({ error: result.reason });
  }

  // signature valid — process transaction
  await processTransfer(user_did, intent.body);
  res.json({ ok: true });
});
```

For the **login flow**, verify the auth proof similarly:

```ts
const r = await verifier.verifyAuthProof({
  user_did,
  signature,
  challenge,
  domain: "orilife.com",
  timestamp,
});
if (r.valid) {
  // Issue your own session for the user — they're authenticated
}
```

---

## Step 5 — Wallet & MAGIC accrual (v0.3.0+)

```ts
import {
  PhoenixKeyClient,
  PREPROD_SLOT_ORIGIN_MS,
  WalletModule,
} from "@phoenixkeydid/phoenixkey-sdk";

// Server-snapshot balance — public endpoint, no auth needed
const balance = await phoenix.wallet.getBalance(userDid);
// → { balance_lovelace, balance_lamp, balance_magic, magic_accrued, magic_rate_per_slot, last_accrual_slot, current_slot }

// UI tick between polls — extrapolate MAGIC accrual since `last_accrual_slot`
const liveMagic = WalletModule.extrapolateAccrued(
  balance,
  Date.now(),
  PREPROD_SLOT_ORIGIN_MS, // or MAINNET_SLOT_ORIGIN_MS
);

// Mint accrued MAGIC to user's wallet — auth required
const { cardano_tx_hash } = await phoenix.wallet.claimMagic();
```

---

## Step 6 — Activation package (200 k₫ → 1001 LAMP + 10 ADA)

```ts
// 1. user clicks "Mua kích hoạt 200 k"
const session = await phoenix.activation.initiate(userWalletAddress);
// → { activation_id, payment_qr_url, proof_chat_url, genie_did, expires_at, ... }

// 2. listen for lifecycle events (payment → activated)
const stream = phoenix.activation.openEventStream(session.activation_id, {
  onEvent: (evt) => {
    if (evt.status === "ACTIVATED") {
      // refresh balance — 1001 LAMP + 10 ADA arrived
      stream.close();
    }
  },
  onError: console.error,
});

// 3. (testnet only) mock-confirm payment with admin token
await phoenix.activation.mockConfirmPayment(session.activation_id, ADMIN_TOKEN);

// — Genie side: after user paid 200 k, sign Cardano tx on mobile then:
const { cardano_tx_hash, status } = await phoenix.activation.submitTx(
  session.activation_id,
  signedCborHex,
);
```

Both modules accept the same `_getSessionToken` getter the rest of the SDK uses
— `setSession(token, meta)` once, all modules read it.

---

## Step 7 — One person, many devices (owner / manager / viewer)

A PhoenixKey user can be logged in on several devices at once (their phone as
`owner`, a second phone or a browser session as `manager`, a read-only client
as `viewer`). If your app receives an `app_token` — via
`POST /auth/token/exchange`, for a `ServiceDID` you own — there are three
things you need to know before you trust it.

**1. `app_token` carries `key_role` — you must gate on it yourself.**
Don't assume every session is a full-power owner session. Verify the token's
signature first (never read a JWT payload without verifying it — that's how
a forged token gets treated as real), then check the role before allowing a
sensitive action:

```ts
import { AppTokenVerifier } from "@phoenixkeydid/phoenixkey-sdk/verifier";
import { keyRoleAtLeast } from "@phoenixkeydid/phoenixkey-sdk";

const verifier = new AppTokenVerifier();

app.post("/orilife/transfer", async (req, res) => {
  const claims = await verifier.verify(req.headers.authorization?.slice(7) ?? "", "did:phoenix:svc:orilife");

  if (!keyRoleAtLeast(claims.key_role, "manager")) {
    return res.status(403).json({ error: "This device session cannot sign transactions" });
  }

  // claims.sub is the user's DID, claims.key_id identifies the device key
  await processTransfer(claims.sub, req.body);
  res.json({ ok: true });
});
```

**2. `key_role: "viewer"` from an old session means "role unknown", not "restricted on purpose".**
Sessions minted before PhoenixKey added role claims — or a token whose
`key_role` claim is missing/garbled — come back as `"viewer"` (the SDK's
`keyRoleFromClaim()` fail-safe never guesses `"owner"` for unclear input).
Don't treat every `"viewer"` as a suspicious or malicious client — it resolves
itself the next time that user logs in fresh. If your app has actions that a
genuine `viewer` role should never be blocked from (read-only stuff), keep
those open regardless of this ambiguity.

**3. A revoked device's `app_token` still works until it expires.**
Revoking a device key (`client.devices.revokeDevice(keyId)`, below) kills
that device's PhoenixKey *session* on its very next call — but any
`app_token` already minted from that session keeps verifying successfully
until its own `exp` (currently 15 minutes) — signature verification alone
can't know a session was revoked afterward. If your app needs near-immediate
revocation (e.g. a compromised device), don't rely on `exp` — re-check with
PhoenixKey (or keep your own short-lived cache of revoked `key_id`s) instead
of trusting the token for its full lifetime.

### Managing your own devices (requires an `owner` session)

```ts
const { devices } = await phoenix.devices.listDevices();
// [{ key_id, device_name, key_role, status, created_at, last_used_at, current }, ...]

await phoenix.devices.renameDevice(someKeyId, "Laptop văn phòng");

await phoenix.devices.revokeDevice(someOldKeyId);
// throws PhoenixKeyError({ code: "last_owner_key" }) if it's your last active owner key —
// go through account recovery instead of revoking your only way in.
```

A `manager`/`viewer` session calling any of these three gets
`PhoenixKeyError({ code: "key_role_forbidden" })` — device management is
owner-only, by backend design, not something the SDK can loosen.

---

## Errors

All SDK methods throw `PhoenixKeyError`:

```ts
import { PhoenixKeyError } from "@phoenixkeydid/phoenixkey-sdk";

try {
  await phoenix.auth.initSession();
} catch (err) {
  if (err instanceof PhoenixKeyError) {
    // err.code:    "session_expired" | "signature_invalid" | "nonce_already_used" |
    //              "key_role_forbidden" | "last_owner_key" | "device_name_invalid" | ...
    // err.status:  HTTP status
    // err.userMessageKey: i18n key — "errors.unauthorized", etc.
  }
}
```

---

## Reference

- Spec: [PhoenixKey_Interface.md v1.4.3](https://github.com/AladinContract/PhoenixKey-Database/blob/main/docs/PhoenixKey_Interface.md)
- Live API: `https://api.phoenixkey.me/api/v1/swagger-ui.html`
- Tokens — `temp_token` 5 min (login SSE), `session_token` 24 h (auth header), `linked_device_token` 30 days (skip QR), `app_token` 15 min (per-`ServiceDID` SSO via `POST /auth/token/exchange` — verify with `AppTokenVerifier`, see Step 7).

License: MIT.
