# @phoenixkeydid/phoenixkey-sdk

SDK tích hợp danh tính và xác thực cho các ứng dụng trong hệ sinh thái **MagicLamp**.

Người dùng đăng nhập bằng **vân tay hoặc khuôn mặt** trên Aladin App — app của bạn nhận `session_token` và `user_did` mà không bao giờ chạm vào private key.

**API Docs:** https://api.phoenixkey.me/docs  
**Full Integration Guide:** https://docs.phoenixkey.me  

---

## Cài đặt

```bash
npm install @phoenixkey/sdk
# hoặc
yarn add @phoenixkey/sdk
```

> **Yêu cầu:** `@microsoft/fetch-event-source` được cài tự động như dependency.

---

## Quickstart

```typescript
import { PhoenixKeyClient } from "@phoenixkey/sdk";

export const phoenix = new PhoenixKeyClient({
  apiKey:  process.env.NEXT_PUBLIC_PHOENIXKEY_API_KEY!, // Lấy tại api.phoenixkey.me/docs
  appId:   "my-app",
  appName: "My App",                                    // Hiển thị trong Aladin khi người dùng xác nhận
});
```

---

## Luồng đăng nhập

Mọi đăng nhập đều đi qua 4 bước sau. SDK xử lý hết — app chỉ cần render QR và lắng nghe kết quả.

```
initSession()  →  render QR  →  openStream()  →  nhận "approved"
      │                              │
      └── temp_token (auth SSE) ─────┘
```

### Bước 1 — Khởi tạo session

```typescript
const { session_id, temp_token, expires_at } = await phoenix.auth.initSession();

// Tạo QR code từ deep link này (dùng thư viện qrcode hoặc tương đương):
const qrPayload = `aladin://auth?session=${session_id}&app=my-app`;
```

> `temp_token` chỉ dùng để xác thực SSE stream và polling — **không phải** session token của người dùng.

### Bước 2 — Mở SSE stream

SSE là cơ chế chính. Server sẽ push event khi người dùng quét vân tay trên Aladin.

```typescript
const stream = phoenix.auth.openStream(session_id, temp_token, {
  onMessage: ({ data }) => {
    if (data.status === "approved") {
      // Lưu session
      phoenix.session.set(data.session_token, data.user_did);

      // Lưu linked device — lần sau không cần QR nữa
      if (data.linked_device_token) {
        phoenix.session.setLinkedDevice(data.linked_device_token);
      }

      stream.close();
      router.push("/dashboard");
    }

    if (data.status === "rejected") {
      stream.close();
      showError("Người dùng từ chối xác nhận");
    }
  },

  // Khi SSE reconnect, poll một lần để bắt event bị miss
  onReconnect: async () => {
    const status = await phoenix.auth.getStatus(session_id, temp_token);
    // Xử lý status như onMessage
  },
});

await stream.connect();

// Cleanup khi component unmount
onDestroy(() => stream.close());
```

### Bước 3 — Xử lý kết quả `approved`

```typescript
// data từ onMessage khi status === "approved":
// {
//   status: "approved",
//   session_token: "eyJhbG...",   // JWT 24h — dùng cho mọi API call tiếp theo
//   user_did: "did:prism:abc...", // DID trên Cardano
//   linked_device_token?: "eyJ..." // JWT 30d — dùng để skip QR lần sau
// }
```

---

## Lần đăng nhập thứ hai (Skip QR)

Khi `linked_device_token` được lưu từ lần trước, app có thể gửi push notification thẳng vào Aladin — người dùng chỉ cần bấm vào thông báo và quét vân tay, không cần mở app và quét QR.

```typescript
if (phoenix.session.hasLinkedDevice()) {
  await phoenix.auth.pushLinkedDevice();
  // Vẫn mở SSE stream để nhận kết quả
  const stream = phoenix.auth.openStream(session_id, temp_token, { ... });
} else {
  // Hiển thị QR như bình thường
}
```

---

## Polling (fallback)

Dùng khi SSE không khả dụng (một số proxy, React Native):

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
}, 2000); // poll mỗi 2 giây
```

---

## Kiểm tra trạng thái đăng nhập

```typescript
// Guard route
if (!phoenix.isLoggedIn()) {
  router.push("/login");
}

// Lấy DID của người dùng hiện tại
const meta = phoenix.session.getSessionMeta();
console.log(meta?.userDid); // "did:prism:abc123..."
```

---

## Đăng xuất

```typescript
phoenix.logout(); // Xoá session_token + linked_device_token khỏi localStorage
router.push("/login");
```

---

## Xử lý lỗi

Mọi method đều throw `PhoenixKeyError` khi thất bại.

```typescript
import { PhoenixKeyError } from "@phoenixkey/sdk";

try {
  await phoenix.auth.initSession();
} catch (err) {
  if (err instanceof PhoenixKeyError) {
    console.log(err.status);       // HTTP status (0 = network failure)
    console.log(err.code);         // "session_expired", "invalid_api_key", ...
    console.log(err.userMessageKey); // "errors.unauthorized", ... (dùng cho i18n)
  }
}
```

### Bảng mã lỗi phổ biến

| `err.code` | `err.status` | Ý nghĩa |
|---|---|---|
| `network_error` | `0` | Mất kết nối |
| `invalid_api_key` | `401` | API key sai — kiểm tra config |
| `session_not_found` | `404` | `session_id` không tồn tại — tạo session mới |
| `session_expired` | `410` | QR hết hạn (5 phút) — tạo session mới |
| `rate_limited` | `429` | Quá nhiều request — retry sau `err.details.retryAfter` giây |
| `invalid_json` | — | Response từ server không phải JSON hợp lệ |

---

## API Reference

### `PhoenixKeyClient`

```typescript
new PhoenixKeyClient(config: PhoenixKeyConfig)
```

| Option | Type | Mặc định | Mô tả |
|---|---|---|---|
| `apiKey` | `string` | *bắt buộc* | API key từ api.phoenixkey.me/docs |
| `appId` | `string` | *bắt buộc* | App ID đã đăng ký |
| `appName` | `string` | *bắt buộc* | Tên hiển thị trong Aladin |
| `apiBaseUrl` | `string` | `https://api.phoenixkey.me` | — |
| `sseBaseUrl` | `string` | `https://api.phoenixkey.me` | — |
| `environment` | `"mainnet" \| "testnet"` | `"mainnet"` | — |

### `client.auth`

| Method | Mô tả |
|---|---|
| `initSession()` | Khởi tạo login session, trả `{ session_id, temp_token, challenge, expires_at }` |
| `openStream(sessionId, tempToken, handlers)` | Mở SSE stream, trả `ResilientSSE` |
| `getStatus(sessionId, tempToken)` | Poll trạng thái một lần, trả `LoginSessionStatus` |
| `pushLinkedDevice()` | Gửi push notification (yêu cầu `hasLinkedDevice() === true`) |

### `client.session`

| Method | Mô tả |
|---|---|
| `set(token, userDid?)` | Lưu `session_token` (TTL đọc từ JWT exp, mặc định 24h) |
| `getSessionToken()` | Trả token nếu còn hạn, `null` nếu hết hạn hoặc chưa đăng nhập |
| `getSessionMeta()` | Trả `{ expiresAt, userDid }` |
| `clearSession()` | Xoá session token |
| `setLinkedDevice(token)` | Lưu `linked_device_token` (TTL 30d) |
| `hasLinkedDevice()` | `true` nếu có linked device còn hạn |
| `clearLinkedDevice()` | Xoá linked device token |
| `isLoggedIn()` | Shortcut: `getSessionToken() !== null` |
| `clearAll()` | Xoá cả session và linked device |

### `client.isLoggedIn()`

Shortcut của `client.session.isLoggedIn()`.

### `client.logout()`

Gọi `clearAll()` — xoá mọi dữ liệu PhoenixKey trong localStorage.

---

## Endpoints thực tế (tham khảo)

Tài liệu đầy đủ tại **https://api.phoenixkey.me/docs**

| Method | Path | Auth header bắt buộc |
|---|---|---|
| `POST` | `/auth/session/init` | `x-api-key` |
| `GET` | `/auth/session/{id}/status` | `x-api-key` + `Authorization: Bearer <temp_token>` |
| `GET` | `/auth/session/{id}/stream` | `x-api-key` + `Authorization: Bearer <temp_token>` |
| `POST` | `/auth/session/push` | `x-api-key` + `Authorization: Bearer <linked_device_token>` |

> **Lưu ý:** SDK tự động đính kèm `x-api-key` vào mọi request. Bạn không cần set header thủ công.

---

## Ví dụ đầy đủ

Xem thư mục [`examples/nextjs/login-page.tsx`](./examples/nextjs/login-page.tsx) để có ví dụ hoàn chỉnh với Next.js 14 App Router.

---

## Liên quan

- **PhoenixKey Core:** `github.com/PhoenixKeyDID/PhoenixKey` — DID registry, smart contracts, Enclave
- **PhoenixKey API:** `github.com/PhoenixKeyDID/PhoenixKey` → `apps/api/`
- **PhoenixKey Database:** `github.com/PhoenixKeyDID/PhoenixKey-Database`
- **Full Docs:** https://docs.phoenixkey.me

---

*© 2026 MagicLamp Network — PhoenixKey SDK v0.1.0*
