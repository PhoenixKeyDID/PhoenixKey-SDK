# PhoenixKey SDK — Integration Plan

> **Mục tiêu:** Đưa SDK `@phoenixkeydid/phoenixkey-sdk` từ trạng thái hiện tại (~700 LOC TypeScript, architecture chỉnh chu nhưng không tương thích với backend đã deploy) thành SDK production-ready cho hệ sinh thái Aladin (OriLife, AladinWork, PhoenixKey-Interface, các app internal khác).
>
> **Phương án kiến trúc đã chốt:** **Path A hybrid** (xem discussion 2026-04-29) — relay-light cho frontend (dùng `/auth/session/*` hiện có), verify-only cho backend (3rd-party tự verify ECDSA bằng pubkey từ DID). KHÔNG đi OAuth2/OIDC full-stack.
>
> **Cập nhật cuối:** 2026-04-29

---

## Mục lục

1. [Bối cảnh](#1-bối-cảnh)
2. [Convention drift — 3 sources of truth lệch nhau](#2-convention-drift)
3. [Gap Analysis SDK vs Backend hiện tại](#3-gap-analysis)
4. [Quyết định kiến trúc cần align](#4-quyết-định-kiến-trúc)
5. [Phase 1 — SDK align với backend (1 tuần)](#5-phase-1)
6. [Phase 2 — Mở rộng SDK surface (1.5 tuần)](#6-phase-2)
7. [Phase 3 — Path A Hybrid cho 3rd-party (1.5 tuần)](#7-phase-3)
8. [Phase 4 — Backend SDK Java/Kotlin (tùy chọn, 1 tuần)](#8-phase-4)
9. [Risks + Open Questions](#9-risks)
10. [Tổng effort + checkpoint](#10-tổng-effort)

---

## 1. Bối cảnh

### 1.1. State hiện tại của các repo

| Repo | Trạng thái | Branch chính | Note |
|---|---|---|---|
| **PhoenixKey-Database** (backend) | Deployed lên `api.phoenixkey.me`, vận hành OK | `remaster` | 23 endpoints, self-host Vault, fee wallet provisioned |
| **PhoenixKey-SDK** (TS SDK) | v0.1.0, kiến trúc chỉnh chu nhưng KHÔNG tương thích với backend deployed | `main` | Sếp viết theo spec PhoenixKey_Interface.md, chưa test E2E |
| **Phoenixkey-Interface** (web phoenixkey.me) | Branch `mock-login` — `/auth/session/*` flow đã được mock, real flow chưa test | `mock-login` | Types snake_case theo spec, chưa hit backend thật |
| **PhoenixKey-Backend** (NestJS legacy) | Out of scope — đã được port hết logic sang Database repo Phase A→G | — | Reference cho Cardano logic |
| **Aladin app mobile** (Tùng) | WIP | — | Không có repo trong workspace local |

### 1.2. Spec dẫn đường

- `docs/PhoenixKey_Interface.md` (v1.4.3, 1514 lines) — UI specification, dùng convention **snake_case**, QR format JSON base64url
- `docs/Update_V1_5.md` — bổ sung nonce + key origin
- `API.md` (backend) — viết sau khi implement, document **camelCase** (mismatch với spec)

### 1.3. Mục tiêu kinh doanh của SDK

- Cho phép app khác trong hệ sinh thái Aladin (OriLife, AladinWork, ...) **tích hợp PhoenixKey để định danh + xác thực user** (qua DID + Hardware Key signature) mà **không cần build lại flow QR/SSE/biometric**
- 3rd-party app KHÔNG cần biết Cardano, không cần BloxBean, không cần BouncyCastle — chỉ gọi 2-3 method SDK
- **Path A hybrid (đã chốt)**: PhoenixKey chỉ làm identity + auth provider, KHÔNG phải full backend cho 3rd-party. Sign request flow vẫn relay qua phoenixkey.me cho 3rd-party web (giống MetaMask), backend SDK verify locally không cần đụng PhoenixKey runtime

---

## 2. Convention drift

### 2.1. Field naming convention

3 nguồn lệch nhau, cần chốt 1:

| Source | Convention | Ví dụ |
|---|---|---|
| Spec `PhoenixKey_Interface.md` (v1.4.3) | **snake_case** | `session_id`, `temp_token`, `session_token`, `user_did`, `linked_device_token` |
| Backend code Java records (deployed) | **camelCase** | `sessionId`, `tempToken`, `sessionToken`, `userDid`, `linkedDeviceToken` |
| Backend doc `API.md` | **camelCase** | match code |
| Web `Phoenixkey-Interface/src/lib/auth.ts` | snake_case | match spec, KHÔNG match backend → Web hiện tại broken nếu un-mock |
| SDK `src/types.ts` | snake_case | match spec, KHÔNG match backend → SDK fail mọi call |

**Recommend chốt:** **snake_case** (theo spec, theo Web Interface hiện có, theo SDK đã viết).

**Cách align rẻ nhất:** thêm 1 dòng vào `application.yml` backend:

```yaml
spring:
  jackson:
    property-naming-strategy: SNAKE_CASE
```

Java records → tự serialize snake_case. Không phải sửa 30+ DTO. Update `API.md` để document snake_case (effort ~30 phút). Web Interface + SDK + Mobile (Tùng) tự nhiên match.

**Risk khi chuyển:**
- Postman collection hiện tại có sample body với mixed case — cần check + update (không ảnh hưởng path/header, chỉ JSON body)
- Bất kỳ existing internal consumer (chưa có ngoài Web mock-login) — không ai khác đang gọi backend production nên risk thấp
- API.md cần cập nhật toàn bộ JSON examples

### 2.2. Response wrapping

**Backend pattern**: tất cả endpoint trả `DataResponse<T>`:
```json
{ "code": 1000, "message": "Session created", "result": { "sessionId": "...", ... } }
```

**SDK fetcher** ([fetcher.ts:78](src/fetcher.ts)) + **Web apiFetch** ([api.ts:124](Phoenixkey-Interface/src/lib/api.ts)) đều `return await res.json() as T` — KHÔNG unwrap `result`.

**Recommend chốt:** Clients adapt — unwrap `result` field ở fetcher level. Lý do:
- Backend pattern nhất quán toàn bộ app, đụng vào risk lớn
- 1 dòng `return body.result ?? body` ở fetcher fix được tất cả
- Web Interface có cùng bug → cùng fix

### 2.3. Error code format

| | Type |
|---|---|
| Backend `ErrorCode.java` | integer: `1301`, `1302`, `1303`, ... |
| SDK + Web expect | string: `"session_expired"`, `"session_not_found"` |

**Recommend chốt:** Clients map locally trong fetcher.

```typescript
// fetcher.ts adds
const ERROR_CODE_MAP: Record<number, string> = {
  1301: "session_not_found",
  1302: "session_expired",
  1303: "session_already_approved",
  1401: "sign_request_not_found",
  1402: "sign_request_expired",
  1403: "signature_invalid",
  // ... full mapping
};
```

Backend giữ integer codes (đã dùng trong activity logs, tracking). Clients có user-friendly string codes cho UX.

### 2.4. QR payload format

| Source | Format |
|---|---|
| Spec PhoenixKey_Interface.md §6.3 line 517-528 | `base64url(JSON({ v: 1, sid, ch, dom, exp }))` — short keys |
| SDK README line 80 | `aladin://auth?session=${session_id}&app=${appId}` — deep link |
| Mobile (Tùng impl unknown) | Likely follow spec |

**Recommend chốt:** Spec wins — base64url JSON with short keys. Lý do:
- Mobile (Tùng) là source of truth cho QR consumer — phải confirm Tùng đã implement format nào
- Short keys giảm QR density (smaller QR = easier scan)
- Carries `challenge` in QR — mobile có thể pre-fetch verify

SDK README + auth.ts cần update.

### 2.5. API key (`x-api-key` header)

- SDK config bắt buộc `apiKey` ([types.ts:9](src/types.ts#L9))
- SDK fetcher gắn `x-api-key` mọi request ([fetcher.ts:33](src/fetcher.ts#L33))
- Backend KHÔNG có middleware đọc/validate header này

**Recommend chốt:** Drop từ SDK config (Phase 1) — đặt thành optional, ignore nếu set. Phase 4 hoặc later khi cần serve external partner thì implement client registration + API key middleware ở backend.

---

## 3. Gap Analysis

### 3.1. Critical (SDK fail runtime với current backend)

| # | Gap | SDK assumption | Backend reality | Severity | Fix in |
|---|---|---|---|---|---|
| 1 | **Field naming** | snake_case | camelCase | 🔴 Mọi field undefined | §2.1 — backend Jackson config |
| 2 | **Response wrap** | raw `{ session_id, ... }` | `{ code, message, result: {...} }` | 🔴 Toàn bộ response shape sai | §2.2 — SDK fetcher unwrap |
| 3 | **`pushLinkedDevice` API** | token in `Authorization: Bearer` header, `POST /auth/session/push` no body | Body `{ sessionId, linkedDeviceToken }` | 🔴 Backend reject 400 | §3.4 — SDK auth.ts:145 |
| 4 | **Error code format** | string `"session_expired"` | integer `1302` | 🟡 Error matching không hoạt động | §2.3 — SDK fetcher map |

### 3.2. Documentation/Cosmetic mismatches

| # | Gap | Source | Impact |
|---|---|---|---|
| 5 | DID format `did:prism:abc...` trong SDK README | docs error | Cosmetic — backend dùng `did:cardano:<network>:<txHash>` |
| 6 | QR payload deep-link `aladin://auth?session=...` | SDK README L80 | Mobile chắc không scan được — cần align với Tùng |
| 7 | API key concept toàn config | SDK types.ts | Misleading — backend không có |
| 8 | `appId`/`appName` chưa được backend dùng | SDK config required | Currently no-op, có thể optional |

### 3.3. Missing surface area

SDK hiện chỉ có `auth` (login flow). Thiếu các flow khác đã implement ở backend:

| Backend endpoint | SDK module | Phase |
|---|---|---|
| `POST /sign/request` | `client.signRequest.create(intent)` | Phase 2 |
| `GET /sign/request/{id}` | (mobile only — không đưa vào SDK 3rd-party) | — |
| `POST /sign/{id}/cancel` | `client.signRequest.cancel(id)` | Phase 2 |
| SSE event `signed` | `client.signRequest.openStream()` | Phase 2 |
| `GET /identity/{did}/pubkey` | `client.identity.getPubkey(did)` | Phase 2 |
| `GET /identity/{did}/document` | `client.identity.resolveDID(did)` | Phase 2 |
| `GET /identity/health` | `client.identity.getHealth()` | Phase 2 |
| `POST /seed/export-request` | `client.seed.requestExport()` | Phase 2 |
| `GET /api/v1/activity-logs` | `client.activity.list(opts)` | Phase 2 |
| `POST /devices/register` | (mobile only — Aladin app, không SDK) | — |
| `GET /tx/estimate` | `client.fees.estimate(type)` | Phase 2 |
| `GET /api/v1/identity/nodes` | `client.network.getNodes()` | Phase 2 (low priority — stub) |
| `POST /support/session/init` | `client.support.initSession()` | Phase 2 (low priority — stub) |
| `POST /keys/{authorize,revoke,rotate}` | (advanced — phase 3, 3rd-party hiếm khi cần) | Phase 3 |
| `POST /guardians/{add,remove}` | Phase 3 | Phase 3 |
| `POST /internal/sync-taad` | Internal — không SDK | — |

### 3.4. `pushLinkedDevice` chi tiết

Backend [SessionController.java:132-140](PhoenixKey-Database/src/main/java/.../controller/SessionController.java):
```java
@PostMapping("/push")
public ResponseEntity<DataResponse<Void>> push(@Valid @RequestBody SessionPushRequest request) {
    sessionService.pushToLinkedDevice(request.sessionId(), request.linkedDeviceToken());
}
```
Body: `{ "sessionId": "...", "linkedDeviceToken": "..." }`

SDK [auth.ts:145-154](src/auth.ts#L145):
```typescript
async pushLinkedDevice(): Promise<void> {
    const device = this._getLinkedDevice?.();
    await this.fetch<void>("/auth/session/push", {
      method: "POST",
      headers: { Authorization: `Bearer ${device.token}` },
      json: false,
    });
}
```

**SDK gửi token trong Authorization header, không có body.** Backend reject 400 (RequestBody required).

Fix: SDK đổi thành body POST. Cần thêm `sessionId` parameter — SDK currently không có (vì lúc push, sessionId mới đang chuẩn bị mở, chưa init). Cần thiết kế lại flow:

**Flow đúng** (theo spec §6.3):
1. User vào `phoenixkey.me/login` lần 2 (đã có linkedDeviceToken trong localStorage)
2. Web call `POST /auth/session/init` → nhận `sessionId` mới
3. Web call `POST /auth/session/push` với `{ sessionId (mới init), linkedDeviceToken }`
4. Backend gửi push notif tới mobile, intent kèm sessionId
5. Mobile mở app, biometric, ký challenge cho sessionId này → POST /approve
6. Web SSE nhận event approved → có sessionToken

SDK API hiện tại fail bước 3 vì thiếu sessionId trong call. Cần fix:

```typescript
// New signature
async pushLinkedDevice(sessionId: string): Promise<void> {
  const device = this._getLinkedDevice?.();
  if (!device) throw new Error("No linked device — show QR instead");
  await this.fetch<void>("/auth/session/push", {
    method: "POST",
    body: JSON.stringify({ session_id: sessionId, linked_device_token: device.token }),
  });
}
```

---

## 4. Quyết định kiến trúc cần align

Trước khi code, cần chốt 5 điểm với sếp/Long:

| # | Quyết định | Recommend | Tại sao |
|---|---|---|---|
| 1 | **Naming convention** | snake_case | Spec + Web + SDK đều assume snake_case. 1 line backend config fix toàn bộ. Update `API.md` ~30 phút. |
| 2 | **Response wrapping** | Keep `DataResponse` wrapper, SDK unwrap | Backend pattern nhất quán toàn app, đụng risk lớn |
| 3 | **Error code** | Backend keep integer, SDK map thành string | Activity logs đã reference integer codes |
| 4 | **API key** | Drop khỏi SDK Phase 1, optional Phase 4 | Backend chưa có middleware, internal Aladin trust được |
| 5 | **QR format** | Spec wins (base64url JSON) | Mobile (Tùng) là source of truth cho QR consumer |

**Action item trước Phase 1:** 30 phút meeting với sếp để chốt 5 điểm trên (hoặc async qua Slack/email với link plan này).

---

## 5. Phase 1 — SDK align với backend (1 tuần)

> **Mục tiêu:** SDK v0.1.1 chạy được end-to-end với backend deployed. Login flow hoạt động.

### 5.1. Backend changes (1 commit, 1-2h work)

**File `application.yml`** — thêm Jackson naming strategy:
```yaml
spring:
  jackson:
    property-naming-strategy: SNAKE_CASE
```

**File `API.md`** — rewrite tất cả JSON example sang snake_case (chỉ field name, không đổi structure).

**File `docs/PhoenixKey.postman_collection.json`** — sweep request bodies, đổi camelCase → snake_case (vd `userDid` → `user_did`).

**Smoke test trên server:**
```bash
docker compose up -d --build app
curl -X POST http://localhost:8080/api/v1/auth/session/init | jq
# Expect: { "code": 1000, "message": "...", "result": { "session_id": "...", "challenge": "...", "temp_token": "...", "expires_at": ... } }
```

**Done criteria:**
- Backend redeploy, response field tất cả snake_case
- Postman collection chạy lại OK
- API.md examples khớp 100% với response thực tế

### 5.2. SDK fetcher refactor (1 ngày)

**File `src/fetcher.ts`:**

```typescript
// ADD: response unwrapping
if (!json || res.status === 204) return undefined as T;

const body = await res.json();

// Unwrap PhoenixKey DataResponse pattern
if (body && typeof body === 'object' && 'code' in body && 'result' in body) {
  if (body.code !== 1000) {
    throw new PhoenixKeyError({
      status: res.status,
      code: ERROR_CODE_MAP[body.code] ?? `code_${body.code}`,
      message: body.message ?? "Unknown error",
      details: body,
    });
  }
  return body.result as T;
}
return body as T;
```

```typescript
// ADD: ERROR_CODE_MAP constant
const ERROR_CODE_MAP: Record<number, string> = {
  1301: "session_not_found",
  1302: "session_expired",
  1303: "session_already_approved",
  1401: "sign_request_not_found",
  1402: "sign_request_expired",
  1403: "signature_invalid",
  2001: "user_not_found",
  2002: "user_did_not_found",
  2003: "user_did_already_exists",
  3001: "key_already_authorized",
  3002: "key_not_found",
  3003: "key_signature_invalid",
  3004: "key_already_revoked",
  3005: "key_status_invalid",
  3006: "nonce_already_used",
  4001: "guardian_not_found",
  4002: "guardian_already_exists",
  4003: "guardian_signature_invalid",
  4004: "guardian_insufficient",
  4005: "guardian_already_revoked",
  5001: "taad_state_not_found",
  5002: "taad_state_stale",
  5003: "taad_reorg_detected",
  5004: "taad_in_recovery_mode",
  5005: "taad_sequence_mismatch",
  5101: "cardano_tx_failed",
  5102: "cardano_resolve_failed",
  9999: "internal_error",
};
```

```typescript
// REMOVE: x-api-key header (no longer required)
// const finalHeaders: Record<string, string> = {
//   Accept: "application/json",
//   "x-api-key": apiKey,  ← DELETE THIS LINE
//   ...
// };
```

### 5.3. SDK config simplify (`PhoenixKeyConfig`)

**File `src/types.ts`:**

```typescript
export type PhoenixKeyConfig = {
  /** @optional — for Phase 4 client registration. Currently ignored. */
  apiKey?: string;
  /** Your app's identifier — used in intent.app_id when calling /sign/request. */
  appId: string;
  /** Display name shown to users in mobile approval screen. */
  appName: string;
  /** Domain bound to authentication challenge (chống cross-domain replay). */
  domain: string;  // ← NEW: required
  apiBaseUrl?: string;
  sseBaseUrl?: string;
  environment?: "mainnet" | "preprod";  // ← was "testnet", align with CARDANO_NETWORK
};
```

**File `src/client.ts`** — adapt constructor.

### 5.4. SDK auth.ts fix `pushLinkedDevice`

```typescript
// auth.ts:145
async pushLinkedDevice(sessionId: string): Promise<void> {
  const device = this._getLinkedDevice?.();
  if (!device) throw new Error("No linked device — show QR instead");
  await this.fetch<void>("/auth/session/push", {
    method: "POST",
    body: JSON.stringify({
      session_id: sessionId,
      linked_device_token: device.token,
    }),
  } as FetchOptions);
}
```

### 5.5. SDK auth.ts add domain to flow

`/auth/session/init` hiện không nhận domain — domain được mobile pass khi approve. Nhưng cho 3rd-party app, domain phải match `config.domain`. Mobile sẽ verify domain bind với challenge signature.

**Implementation note:** Thực ra backend `/auth/session/init` không cần domain — chỉ tạo challenge. Mobile bind domain trong signature. SDK lưu `config.domain` để Phase 3 build QR payload (domain in QR).

Không cần đổi backend. Chỉ document trong SDK rằng `domain` config sẽ được dùng cho QR.

### 5.6. SDK QR builder method

Thêm helper trong `auth.ts`:

```typescript
/**
 * Build QR payload theo spec §6.3 — base64url JSON.
 * Web SDK consumer encode chuỗi này thành QR code (dùng `qrcode` library).
 */
buildQrPayload(init: LoginSessionInit, domain: string): string {
  const payload = {
    v: 1,
    sid: init.session_id,
    ch: init.challenge,
    dom: domain,
    exp: init.expires_at,
  };
  const json = JSON.stringify(payload);
  // base64url encode
  return btoa(json).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
```

### 5.7. Update SDK README

- Bỏ section "Get a GitHub Personal Access Token" + "Configure npm" (hoặc giữ nếu vẫn publish GHPackages — confirm với sếp)
- Xóa reference `apiKey` (config entry vẫn còn nhưng optional)
- Update QR section: `aladin://auth?session=...` → `phoenix.auth.buildQrPayload(init, domain)` + render base64url JSON
- DID format: `did:prism:...` → `did:cardano:<network>:<txHash>`
- Field names: snake_case throughout (đã đúng, just verify)

### 5.8. PoC test

Tạo `examples/login-poc/` (vanilla HTML + qrcode lib):

```html
<script type="module">
  import { PhoenixKeyClient } from '@phoenixkeydid/phoenixkey-sdk';
  import QRCode from 'qrcode';
  
  const phoenix = new PhoenixKeyClient({
    apiBaseUrl: 'https://api.phoenixkey.me',
    appId: 'sdk-poc',
    appName: 'SDK PoC',
    domain: 'localhost',
    environment: 'preprod',
  });
  
  document.getElementById('login').onclick = async () => {
    const init = await phoenix.auth.initSession();
    const qrPayload = phoenix.auth.buildQrPayload(init, 'localhost');
    QRCode.toCanvas(document.getElementById('qr'), qrPayload);
    
    const stream = phoenix.auth.openStream(init.session_id, init.temp_token, {
      onMessage: ({ data }) => {
        if (data.status === 'approved') {
          console.log('Logged in!', data);
          phoenix.session.set(data.session_token, data.user_did);
          stream.close();
        }
      },
    });
    await stream.connect();
  };
</script>
```

**Done criteria Phase 1:**
- [ ] Backend snake_case + redeployed, smoke test pass
- [ ] SDK v0.1.1 build clean (`pnpm build` success)
- [ ] PoC HTML chạy local hit api.phoenixkey.me — `initSession()` trả response đúng shape (snake_case, unwrapped)
- [ ] PoC QR render được, có thể decode lại đúng JSON
- [ ] Postman simulate mobile approve → SDK SSE nhận event `approved` đúng — flow E2E hoạt động (chưa cần mobile thật)
- [ ] PhoenixKey-Interface (web phoenixkey.me) update theo cùng convention — un-mock được login page

### 5.9. Effort breakdown Phase 1

| Day | Task | Owner |
|---|---|---|
| 1 | Backend Jackson config + redeploy + API.md update | Backend dev (Long?) |
| 2 | SDK fetcher refactor (unwrap, error map, drop apiKey) | SDK dev |
| 3 | SDK auth.ts fix (pushLinkedDevice body, buildQrPayload helper, types update) | SDK dev |
| 4 | SDK examples/login-poc PoC | SDK dev |
| 5 | E2E test với Postman simulate mobile + bug fix | SDK + backend |
| 6 | Web Interface un-mock (`/login` real flow) — verify cùng SDK pattern | Web dev (Long) |
| 7 | Buffer + documentation update | — |

---

## 6. Phase 2 — Mở rộng SDK surface (1.5 tuần)

> **Mục tiêu:** SDK v0.2.0 cover full read-side + sign-request flow. Sẵn sàng cho 3rd-party app integrate basic use case (login + request signature).

### 6.1. SDK module structure

```
src/
├── client.ts                        # Main client
├── auth.ts                          # Phase 1 (login)
├── signRequest.ts                   # NEW — Phase 2
├── identity.ts                      # NEW — Phase 2
├── activity.ts                      # NEW — Phase 2
├── seed.ts                          # NEW — Phase 2
├── network.ts                       # NEW — Phase 2 (LampNet nodes)
├── support.ts                       # NEW — Phase 2 (Get LAMP)
├── fees.ts                          # NEW — Phase 2
├── session.ts                       # Phase 1 (storage)
├── sse.ts                           # Phase 1 (ResilientSSE)
├── fetcher.ts                       # Phase 1 (HTTP + auth)
├── types.ts                         # All types
└── index.ts                         # Public exports
```

### 6.2. `signRequest` module — flow chính cho 3rd-party

```typescript
// SDK API
const phoenix = new PhoenixKeyClient({...});

// 3rd-party app yêu cầu user ký giao dịch
const { request_id, expires_at } = await phoenix.signRequest.create({
  session_id: currentSessionId,    // session active của user
  intent: {
    type: 'TRANSFER',
    body: { amount: '100 LAMP', to: 'addr1q...' },
    domain: 'orilife.com',
    app_id: 'orilife-web-v1',
    nonce: phoenix.signRequest.randomNonce(),  // helper SDK
    timestamp: Math.floor(Date.now() / 1000),
    display_text: 'Transfer 100 LAMP to shop',
  },
});

// Listen for mobile approval
const stream = phoenix.signRequest.openStream(currentSessionId, sessionToken, {
  onMessage: ({ type, data }) => {
    if (type === 'signed' && data.request_id === request_id) {
      console.log('User signed:', data.signature);
      // 3rd-party backend verify signature locally (Phase 3 — verify SDK)
    }
    if (type === 'cancelled') {
      console.log('User cancelled');
    }
  },
});

// Optional cancel
await phoenix.signRequest.cancel(request_id);
```

**Implementation note:** SSE event mới — backend hiện emit qua `SseEmitterRegistry.emit(sessionId, "signed", ...)`. SDK reuse logic từ `auth.openStream` — chia sẻ `ResilientSSE` instance.

### 6.3. `identity` module

```typescript
const pubkey = await phoenix.identity.getPubkey('did:cardano:preprod:...');
// → { public_key_hex: '02...', key_role: 'owner' }

const doc = await phoenix.identity.resolveDID('did:cardano:preprod:...');
// → W3C DID Document JSON

const health = await phoenix.identity.getHealth();   // requires Bearer
// → { seed_exported, exported_at, active_key_count, guardian_count }
```

### 6.4. Các module còn lại

- `activity.list({ limit, cursor, filter, range })` — paginated activity logs
- `seed.requestExport({ session_id, display_text? })` — trigger seed export sign-request
- `fees.estimate(type)` — Cardano fee estimate (stub)
- `network.getNodes()` — LampNet 12 mock nodes
- `support.initSession()` — ProofChat placeholder

### 6.5. Done criteria Phase 2

- [ ] All modules implement với type-safe TypeScript
- [ ] Unit test mỗi module (mock fetch, verify request shape + response parsing)
- [ ] Integration test: full flow `initSession → approve → signRequest.create → mobile sign → SSE signed event` end-to-end với backend thật
- [ ] Examples cho 3 use case: login-only, login+sign, identity-resolve
- [ ] README update với full API reference

### 6.6. Effort Phase 2

| Day | Task |
|---|---|
| 1-2 | `signRequest` module + SSE multiplex |
| 3 | `identity` + `activity` modules |
| 4 | `seed`, `fees`, `network`, `support` (low-effort wrappers) |
| 5-6 | Unit tests + integration tests |
| 7 | Examples + README v0.2.0 |
| 8 | Buffer |

---

## 7. Phase 3 — Path A Hybrid cho 3rd-party (1.5 tuần)

> **Mục tiêu:** SDK v0.3.0 hỗ trợ 3rd-party app (OriLife, AladinWork) tích hợp **mà không cần PhoenixKey relay sign-request**. 3rd-party backend verify signature LOCALLY (path A pure cho server-side).

### 7.1. Backend changes (small)

3 thay đổi nhỏ ở [PhoenixKey-Database](../PhoenixKey-Database):

| # | Change | File | LOC |
|---|---|---|---|
| 1 | Dynamic CORS đọc origin từ `clients` table (hoặc env) | `WebConfig.java` | ~20 |
| 2 | SSE event `approved` include `signature` + `challenge` + `timestamp` (cho 3rd-party verify locally) | `SessionServiceImpl.java:170-174` | ~5 |
| 3 | Activity log gắn `domain` metadata để biết user login app nào | `SessionServiceImpl.java:182` | ~2 |

**KHÔNG cần** (per discussion §4):
- Client registration table với DB
- API key middleware
- OAuth2 redirect flow
- JWKS endpoint
- Token scopes
- Per-client rate limit (nginx global rate limit OK)

### 7.2. SDK Verifier module (chính của Phase 3)

3rd-party backend dùng SDK để verify signature **không cần đụng PhoenixKey runtime**:

```typescript
import { PhoenixKeyVerifier } from '@phoenixkeydid/phoenixkey-sdk/verifier';

const verifier = new PhoenixKeyVerifier({
  blockfrostKey: process.env.BLOCKFROST_API_KEY,  // optional, để resolve DID Document
  network: 'mainnet',
  pubkeyResolver: 'phoenixkey',  // 'phoenixkey' | 'cardano' (resolve from DID directly)
});

// Verify auth proof (login flow)
const result = await verifier.verifyAuthProof({
  user_did: 'did:cardano:mainnet:abc...',
  signature: 'der_hex',
  challenge: 'hex_32',
  domain: 'orilife.com',
  timestamp: 1714201200,
});
// → { valid: boolean, user_did, signed_at }

// Verify intent signature (sign-request flow)
const result2 = await verifier.verifyIntent({
  user_did: 'did:cardano:mainnet:abc...',
  intent: { type: 'TRANSFER', ... },  // canonical JSON
  signature: 'der_hex',
});
// → { valid: boolean }
```

**Implementation key:**
- Resolve pubkey từ DID — 2 sources possible:
  - PhoenixKey API `GET /identity/{did}/pubkey` (default, requires PhoenixKey server live)
  - Cardano direct via Blockfrost (`pubkeyResolver: 'cardano'`) — đọc inline datum từ tx hash trong DID, decode W3CDIDDocument, lấy pubkey. **Decentralized — không phụ thuộc PhoenixKey server**.
- ECDSA secp256k1 verify locally bằng `@noble/curves/secp256k1` (lightweight, no Node-specific deps, browser+Node compatible)
- Canonical JSON serialization (sort keys) match backend `SignRequestServiceImpl.canonicalIntentBytes()`

### 7.3. Sub-package `@phoenixkeydid/phoenixkey-sdk/verifier`

Tách SDK thành 2 entry points:
- `@phoenixkeydid/phoenixkey-sdk` — full SDK (browser, includes login/sign/all modules)
- `@phoenixkeydid/phoenixkey-sdk/verifier` — verify-only (Node + browser, lightweight, ~50KB instead of ~200KB)

**Lý do tách:** 3rd-party backend (OriLife BE) chỉ cần verifier, không cần SSE/localStorage/DOM.

```json
// package.json
"exports": {
  ".": {
    "import": "./dist/index.mjs",
    "require": "./dist/index.js",
    "types": "./dist/index.d.ts"
  },
  "./verifier": {
    "import": "./dist/verifier.mjs",
    "require": "./dist/verifier.js",
    "types": "./dist/verifier.d.ts"
  }
}
```

### 7.4. Reference flow doc

Tạo `docs/INTEGRATION.md` document cụ thể:

**Use case 1: OriLife login với PhoenixKey**
```
1. User vào OriLife.com, click "Sign in with PhoenixKey"
2. OriLife frontend (SDK) call phoenix.auth.initSession()
3. SDK build QR payload với domain='orilife.com', render QR
4. User mở Aladin app, scan QR
5. Mobile show "OriLife.com is requesting authentication" + biometric
6. Mobile sign challenge:domain:timestamp với Hardware Key
7. Mobile POST /auth/session/{id}/approve
8. Backend verify signature, mint session_token, emit SSE event với 
   {session_token, signature, challenge, timestamp, user_did}
9. OriLife frontend SDK nhận event → forward {user_did, signature, challenge, 
   timestamp} sang OriLife backend
10. OriLife backend verify với @phoenixkeydid/phoenixkey-sdk/verifier:
    - Resolve pubkey từ user_did (qua Blockfrost direct hoặc PhoenixKey API)
    - Verify ECDSA signature trên `challenge:orilife.com:timestamp`
    - Trust user_did nếu valid → tạo session OriLife riêng
```

**Use case 2: OriLife yêu cầu user ký intent**
```
1. User đang trong session OriLife, thực hiện hành động cần signature 
   (vd: thanh toán)
2. OriLife backend tạo intent JSON: {type: 'TRANSFER', body, domain: 
   'orilife.com', app_id: 'orilife-web-v1', nonce, timestamp, display_text}
3. OriLife frontend SDK call phoenix.signRequest.create(intent) — relay qua 
   PhoenixKey
4. PhoenixKey emit push notification tới mobile (qua linked device hoặc QR)
5. Mobile show display_text + biometric → ký canonical intent JSON
6. Mobile POST /sign/{id}/approve với signature
7. PhoenixKey emit SSE event 'signed' với {request_id, signature, public_key_hex}
8. OriLife frontend SDK forward {intent, signature} sang OriLife backend
9. OriLife backend verify với verifier SDK:
   - Canonical intent JSON
   - Verify ECDSA signature
   - Verify nonce chưa dùng (in OriLife DB)
   - Verify timestamp ±60s
   - Process transaction
```

### 7.5. Done criteria Phase 3

- [ ] Verifier SDK build, sub-package export hoạt động
- [ ] Backend 3 changes deployed
- [ ] CORS test pass với origin orilife.com (giả lập)
- [ ] E2E demo: mock OriLife backend (Express) verify signature từ SDK PoC frontend
- [ ] Decentralized resolver (Cardano direct via Blockfrost) hoạt động — không cần PhoenixKey server
- [ ] `INTEGRATION.md` cover 2 use case + sample code

### 7.6. Effort Phase 3

| Day | Task |
|---|---|
| 1 | Backend 3 changes — CORS dynamic, SSE payload, log domain |
| 2-3 | Verifier SDK: ECDSA verify + DID pubkey resolver (2 sources) |
| 4 | Sub-package build setup (tsup multi-entry) |
| 5 | Demo OriLife mock backend Express |
| 6 | E2E test full flow (PoC frontend + OriLife BE) |
| 7-8 | INTEGRATION.md + sample apps |
| 9 | Buffer + bug fix |

---

## 8. Phase 4 — Backend SDK Java/Kotlin (tùy chọn, 1 tuần)

> **Mục tiêu:** Hệ sinh thái Aladin có nhiều backend Java/Kotlin (AladinWork). Ship Java verifier SDK để các backend đó dùng được mà không phải port logic từ TS.

### 8.1. Repo + structure

Tạo repo riêng: `phoenixkey-sdk-java` (hoặc đặt trong workspace AladinContract). Không nằm trong PhoenixKey-SDK TS repo (clean separation).

```
phoenixkey-sdk-java/
├── pom.xml
├── README.md
└── src/main/java/me/phoenixkey/sdk/
    ├── PhoenixKeyVerifier.java
    ├── DIDResolver.java
    ├── SignatureVerifier.java
    └── canonical/CanonicalJson.java
```

### 8.2. API tương đương verifier TS

```java
PhoenixKeyVerifier verifier = PhoenixKeyVerifier.builder()
    .blockfrostApiKey("mainnet...")
    .network(Network.MAINNET)
    .pubkeyResolver(Resolver.PHOENIXKEY)  // hoặc CARDANO
    .build();

VerifyResult result = verifier.verifyAuthProof(VerifyAuthProofRequest.builder()
    .userDid("did:cardano:mainnet:abc...")
    .signature("der_hex")
    .challenge("hex_32")
    .domain("orilife.com")
    .timestamp(1714201200L)
    .build());

if (result.isValid()) {
    String userDid = result.getUserDid();
    // Trust user
}
```

### 8.3. Implementation reuse

- BouncyCastle ECDSA (đã dùng trong backend Java [SignatureServiceImpl.java](PhoenixKey-Database/src/main/java/.../service/crypto/SignatureServiceImpl.java))
- BloxBean cardano-client-lib cho Cardano direct resolver
- Jackson canonical mapper (`SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS`)
- Dependencies từ backend repo có thể copy 1:1

### 8.4. Done criteria Phase 4

- [ ] Maven artifact published (Maven Central hoặc internal Aladin registry)
- [ ] Sample Spring Boot app demo verify
- [ ] Cùng test vectors với verifier TS — giá trị giống nhau bit-by-bit
- [ ] README + javadoc

### 8.5. Effort Phase 4

5-7 ngày work. Có thể parallelize với Phase 3.

---

## 9. Risks + Open Questions

### 9.1. Risks

| Risk | Severity | Mitigation |
|---|---|---|
| Backend đổi sang snake_case break Postman tests + Web mock-login | 🟡 | Test Postman trước deploy; Web đang mock-login nên không ảnh hưởng |
| Mobile (Tùng) đã implement với convention khác | 🔴 | **Cần confirm với Tùng trước Phase 1** — chốt convention chung |
| 3rd-party app (OriLife) chưa sẵn sàng integrate, SDK ship rỗi | 🟢 | Phase 3 nên parallelize với 1 partner thực tế (OriLife) test ngay |
| SDK convention drift sau Phase 1 — có thể SDK cũ phải maintain | 🟡 | Bump major version (v0.x → v1.0.0), document breaking changes rõ |
| Decentralized resolver (Blockfrost) phụ thuộc Blockfrost uptime | 🟢 | Phase 3+ có thể support multiple Cardano backend (Koios fallback) |
| Backend `domain` field hiện không validate — attacker pass domain bất kỳ | 🟡 | Phase 3 — config `allowed_domains` per client, hoặc dùng CORS Origin header verify |

### 9.2. Open Questions (cần align với sếp/Long/Tùng)

1. **[BLOCKING]** Naming convention — sếp confirm snake_case OK? Mobile Tùng implement convention nào?
2. **[BLOCKING]** SDK package distribution — GitHub Packages tiếp tục, hay chuyển npm public registry?
3. **[BLOCKING]** Web Interface un-mock timeline — có thể đồng bộ với Phase 1 SDK không?
4. SDK v0.x branding — keep `@phoenixkeydid/phoenixkey-sdk` hay rename `@aladin/phoenixkey-sdk`?
5. License — README package.json viết MIT, có giữ MIT cho 3rd-party Aladin internal không? (MIT là OK, nhưng confirm).
6. Phase 4 Java SDK có cần ship cùng Phase 3 không? Hay đợi AladinWork backend ready mới làm?
7. Versioning policy — SemVer strict? Tag v0.0.x dev → v0.x.x trial → v1.0.0 prod ready?
8. CI/CD — test SDK trên backend deployed (api.phoenixkey.me) hay self-host backend test instance?
9. Mobile QR scanner — confirm Tùng đã handle base64url JSON format (spec §6.3)?
10. Push notification production — chưa wire FCM/APNs (PushServiceStub log only). SDK có cần push thật cho `pushLinkedDevice` work end-to-end?

### 9.3. Out of scope / Phase 5+

Để tránh scope creep, KHÔNG làm trong Phase 1-4:

- OAuth2 / OIDC compliant server
- Client registration table + admin UI
- Multi-tenant per-client rate limit (dùng nginx global trước)
- API key authentication (chỉ làm khi external partner thật cần)
- Anti-phishing intent display — server-side template generation (mobile show as-is đủ cho internal apps)
- Mobile SDK Kotlin/Swift — Tùng tự làm cho Aladin app
- Sign-request retry / queue logic — SDK throw, app tự retry
- Mock server cho SDK development — dùng api.phoenixkey.me preprod thật

---

## 10. Tổng effort + checkpoint

### 10.1. Timeline

```
Week 1   ┃ Phase 1 — SDK align with backend          [BLOCKING]
Week 2   ┃ Phase 1 buffer + Phase 2 start
Week 3   ┃ Phase 2 — Mở rộng SDK surface
Week 4   ┃ Phase 2 wrap-up + Phase 3 start
Week 5   ┃ Phase 3 — Path A Hybrid (verifier SDK)
Week 6   ┃ Phase 3 wrap-up + Phase 4 (parallel với 3rd-party pilot)

Tổng: ~6 tuần với 1 dev focus full-time, hoặc ~10 tuần parallel với feature work.
```

### 10.2. Phase gate criteria (cần pass mới sang Phase tiếp theo)

| Phase | Gate criteria |
|---|---|
| 1 → 2 | E2E login flow E2E hoạt động với PoC HTML; Web Interface un-mock cùng convention |
| 2 → 3 | Sign-request flow E2E với mobile; 5+ apps (mock) gọi SDK successfully trong test |
| 3 → 4 | OriLife (real partner) integrate verifier SDK production; pass 1 tuần soak test |
| 4 → ship | Java SDK ship + AladinWork integrate ít nhất 1 endpoint với verifier |

### 10.3. Decision points + checkpoints

- **End of Phase 1:** Demo cho sếp + decide có release public package hay tiếp tục internal
- **End of Phase 2:** Demo cho team 3rd-party (OriLife eng) — gather feedback API ergonomics
- **End of Phase 3:** Production pilot OriLife — soak 1-2 tuần trước khi nâng major version
- **End of Phase 4:** Ship v1.0.0 + announcement nội bộ Aladin

---

## Appendix A — Backend convention reference

Sau Phase 1, **API.md** + **PhoenixKey.postman_collection.json** đều phải đồng bộ với convention sau:

- **Naming**: snake_case toàn bộ JSON field
- **Wrapping**: `{ "code": <int>, "message": "...", "result": {...} | null }`
- **Error codes**: integer (xem `ErrorCode.java`), client map sang string
- **DID format**: `did:cardano:<network>:<txHash>`
- **Time format**: epoch seconds (`expires_at`, `timestamp`)
- **UUID format**: UUIDv7 (timestamp-prefixed) cho cursor pagination
- **HTTP status**: theo ErrorCode.java mapping (1301→404, 1302→410, 1403→403, ...)

## Appendix B — File checklist

Files sẽ được sửa/tạo trong Phase 1-3:

### Backend (`PhoenixKey-Database`)

- [ ] `src/main/resources/application.yml` — thêm Jackson config (Phase 1)
- [ ] `API.md` — rewrite snake_case (Phase 1)
- [ ] `docs/PhoenixKey.postman_collection.json` — rewrite snake_case bodies (Phase 1)
- [ ] `src/main/java/.../config/WebConfig.java` — dynamic CORS (Phase 3)
- [ ] `src/main/java/.../service/session/SessionServiceImpl.java` — SSE payload + log domain (Phase 3)

### SDK (`PhoenixKey-SDK`)

- [ ] `src/fetcher.ts` — unwrap result + error code map (Phase 1)
- [ ] `src/types.ts` — adjust config + error types (Phase 1)
- [ ] `src/auth.ts` — fix pushLinkedDevice + buildQrPayload helper (Phase 1)
- [ ] `src/client.ts` — adjust constructor (Phase 1)
- [ ] `src/signRequest.ts` — NEW (Phase 2)
- [ ] `src/identity.ts` — NEW (Phase 2)
- [ ] `src/activity.ts` — NEW (Phase 2)
- [ ] `src/seed.ts`, `src/fees.ts`, `src/network.ts`, `src/support.ts` — NEW (Phase 2)
- [ ] `src/verifier.ts` — NEW sub-package (Phase 3)
- [ ] `package.json` — multi-entry exports (Phase 3)
- [ ] `README.md` — rewrite (Phase 1, 2, 3)
- [ ] `examples/login-poc/` — NEW (Phase 1)
- [ ] `examples/orilife-mock/` — NEW (Phase 3)
- [ ] `docs/INTEGRATION.md` — NEW (Phase 3)

### Web (`Phoenixkey-Interface`)

- [ ] `src/lib/api.ts` — unwrap result (Phase 1)
- [ ] `src/app/login/page.tsx` — un-mock (Phase 1)
- [ ] Snake_case alignment trong types — đã có sẵn

---

**Review status:** _Pending sếp + Long approval._

**Next action:** Chốt 5 điểm decision §4 → kick off Phase 1.
