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

const verifier = new PhoenixKeyVerifier({ network: "mainnet" });

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

## Errors

All SDK methods throw `PhoenixKeyError`:

```ts
import { PhoenixKeyError } from "@phoenixkeydid/phoenixkey-sdk";

try {
  await phoenix.auth.initSession();
} catch (err) {
  if (err instanceof PhoenixKeyError) {
    // err.code:    "session_expired" | "signature_invalid" | "nonce_already_used" | ...
    // err.status:  HTTP status
    // err.userMessageKey: i18n key — "errors.unauthorized", etc.
  }
}
```

---

## Reference

- Spec: [PhoenixKey_Interface.md v1.4.3](https://github.com/AladinContract/PhoenixKey-Database/blob/main/docs/PhoenixKey_Interface.md)
- Live API: `https://api.phoenixkey.me/api/v1/swagger-ui.html`
- Tokens — `temp_token` 5 min (login SSE), `session_token` 24 h (auth header), `linked_device_token` 30 days (skip QR).

License: MIT.
