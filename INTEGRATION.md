# PhoenixKey — Platform Integration Manifest

> **Là gì**: Khai báo tích hợp của platform **PhoenixKey** — tuân thủ **MagicLamp Platform Integration Standard** (L1 Ecosystem Standard, `SuperApp/Specs/INTEGRATION-STANDARD.md`, v0.1). File này KHÔNG định nghĩa lại chuẩn; nó là bản CONFORMANCE của PhoenixKey theo chuẩn đó.
> **Kiểu tích hợp**: `silent` (§1.3) — PhoenixKey không chiếm UI; cung service API + capability cho module khác. KHÔNG khai `entrypoint`/`route`/`icon`/`navSlot`.
> **Vai trò đặc biệt**: PhoenixKey DID là **root danh tính toàn hệ** (§3.1) — mọi module tiêu thụ danh tính qua service API của PhoenixKey.
> **Owner**: Aladin (founder) · Phoenix agent giữ interface contract. **Cập nhật**: 2026-09-08 (đo lại JWKS trên prod và dán số đo thô: 200 dưới `/api/v1`, 404 ở gốc miền; **gỡ câu "mặc định của `AppTokenVerifier` đã trỏ đúng" — câu đó SAI**, mặc định khi ấy là gốc miền trần và trả 404, đã vá ở cùng đợt; thêm §4.2 vòng nối đầy đủ cho một trang web bên thứ ba, gồm mắt "nhận thẻ ở trang callback rồi xoá khỏi thanh địa chỉ" trước nay chưa có mã ở đâu cả).
> **Nhà canonical**: file này ở **PhoenixKey-SDK** (repo công khai, versioned) — nơi mọi integrator bên ngoài + SuperApp fetch. Bản ở root `PhoenixKeyDID/PhoenixKey-Integration.md` chỉ là con trỏ cho người đọc.

---

## 1. Module Manifest (§1 — silent)

```jsonc
{
  "schemaVersion": "1.0",
  "moduleId": "phoenixkey.identity",        // reverse-DNS, duy nhất toàn ecosystem
  "version": "0.1.0",
  "displayName": { "vi": "PhoenixKey", "en": "PhoenixKey" },
  "integrationKind": "silent",              // §1.3 — cung service API, không UI

  // Capability PhoenixKey YÊU CẦU từ fabric (tối thiểu — nó là provider danh tính) —
  // default-deny, cưỡng chế qua runtime broker (§3.4)
  "capabilities": {
    "data":    ["read:did", "write:did.anchor", "read:wallet", "write:wallet.tx"],
    "wallet":  ["read:balance", "write:sign"],   // trust-tier cao (SG5) — gated
    "biometric": ["verify"],                       // Secure Enclave, local-only
    "network": ["fabric.api"],                      // KHÔNG free-form egress
    "host": []
  },

  "mergePolicy": "on-chain-total-order",     // anchor DID theo thứ tự on-chain
  "configSchemaRef": "./config.schema.json", // (declarative thuần — §4.1)
  "billingHooks": [],                         // phí mạng nội bộ, không B2C ở tầng này
  "trustTier": 3,                             // provider danh tính lõi (không phải module tier-0)
  "stakeBondLamp": "0",
  "signature": "<code-signing sig — verify ở Registry>"
}
```

## 2. Service API surface PhoenixKey CUNG CẤP (silent → module khác tiêu thụ)

Mọi capability đi qua **runtime broker per-call, default-deny** (§3.4); module xin scope hẹp trong manifest của chúng.

| Capability | Mô tả | Ràng buộc chuẩn |
|---|---|---|
| `identity.resolve` / `identity.auth` | Resolve `did:phoenix:…`, cấp token danh tính (audience-bound cho kênh 3, §5.1) | DID gốc + sinh trắc KHÔNG rời Secure Enclave; ký secp256k1/Ed25519 |
| `wallet.view` | Ví 2 loại: **Ví Tiêu chuẩn** (HD/seed CIP-1852, tương thích ví ngoài) + **Ví Phượng hoàng** (custody theo DID, khôi phục guardian). Số dư ADA + native asset động | chain-data qua fabric API (INV-1) |
| `wallet.send` | Gửi có màn xác nhận đầy đủ chống ký-mù: hiện recipient/amount/fee/**policy id** + cảnh báo token trùng tên khác policy | ký qua broker (sinh trắc+PIN); seed/KEK không rời enclave |
| `wallet.receive` / `wallet.history` | Địa chỉ+QR / lịch sử giao dịch | history = chain-data qua fabric API |
| `activation.wakeme` | Tạo ví Phoenix → nạp 1001 LAMP | production: ví treasury có kiểm soát + idempotency theo DID + qua fabric API, KHÔNG seed thô |
| `staking.*` | Multi-pool staking, rút thưởng, DRep delegate/vote + Governance Action | — |
| `pool.operator` | SPO tạo/rút pool + rotate KES trên mobile | máy CHỈ ký, node sinh KES; 2FA sinh trắc; timelock retire tuỳ chỉnh |
| `dapp.connect` | Kết nối dApp/sàn Cardano qua WebView + CIP-30 shim | decode đủ 17 loại certificate trước khi ký; cert lạ → chặn |
| `knowme.face2fa.enroll` / `.verify` / `.policy` | Sinh trắc khuôn mặt lớp-2 (Knowme): enroll template gắn DID, verify theo purpose → `{pass, loa, attestation}`, chính sách per-DID. Ống kính (camera+liveness) **tiêu thụ từ MobileCore** (SuperApp), Phoenix match ON-DEVICE | template mã hoá local KHÔNG rời enclave; on-chain CHỈ `H(template‖salt_DID)`+loa (INV-3); attestation = HW_Key ký `{did,purpose,loa,ts,nonce}`. Thiết kế: [[knowme-face-2fa]] |

## 2.1 Trạng thái endpoint LIVE (backend `PhoenixKey-Database`, base `/api/v1`)

Bảng cho integrator (SuperApp) biết **build được vào cái gì NGAY**. Đối chiếu ngày **2026-08-05** với `GET /api/v1/v3/api-docs` trên prod — **66 route đang phục vụ**.

Cột trạng thái:
- `READY` — gọi được, có nghiệp vụ thật đằng sau.
- `KHUNG` — route đã công bố nhưng trả mã **9501 "Endpoint not yet implemented"**; đang chờ phụ thuộc ngoài. Client nối trước được, chỉ cần xử mã 9501 như "chưa bật".
- `CHỜ MERGE` — mã đã viết, PR mở, chưa lên prod.
- `MISSING` — chưa có route.

| Năng lực | Endpoint (prefix `/api/v1`) | Trạng thái |
|---|---|---|
| **Tạo DID** | `POST /identity/register` (Person) · `POST /identity/org/create` · `/identity/org/founding` · `POST /identity/asset/create` · resolve `GET /identity/{did}/document` · `/identifiers/{did}` (W3C) · `/identity/{did}/pubkey` · `/identity/{did}/status` | **READY** |
| **Chữ ký phiên web** (QR-pairing) | `POST /auth/session/init` → `GET /auth/session/{id}/stream` (SSE) → mobile `POST /auth/session/{id}/approve` → web nhận `session_token` (JWT **24 giờ** — `PHOENIXKEY_SESSION_TTL_SECONDS`, mặc định 86400) + `linked_device_token` (30 ngày); SSO `POST /auth/token/exchange` → `app_token` 15 phút, xem §"Đổi thẻ phiên lấy thẻ app" | **READY** |
| **Nhận ADA / xem số dư** | `POST /wallet/register` (Phoenix custody) · `POST /wallet/standard/register` (CIP-1852) · `GET /wallet/{did}/all` · `GET /wallet/standard/{did}` (số dư ADA/LAMP/CARP từ Blockfrost). 🔒 **Ba endpoint GET đọc ví — `/wallet/{did}/balance`, `/wallet/standard/{did}`, `/wallet/{did}/all` — bắt Bearer `session` VÀ ép `caller_did == path_did`; DID khác trả 401.** Không có đường đọc ví của người khác: liên kết DID → địa chỉ → số dư là oracle liên kết danh tính, không phải dữ liệu công khai. **Số lượng on-chain trả về là JSON _string_** (oildrop/lovelace/nanoMAGIC) — xem §"Hợp đồng số lớn" | **READY** (string-serialize: Database PR #102 đã merge 2026-07-30) |
| **GetLAMP v5** (khoá 1001 LAMP vào vault) | `POST /wakeme/build` (dựng tx chưa ký vào-vault + khoá `conditional_lamp`) → client Enclave ký → `POST /wakeme/submit`. **Đường chính thống là `/wakeme/*`** (`WakemeController`); `/activation/getlamp/{build,submit}` là **bí danh cũ** vẫn còn bind ở `ActivationVaultController` — đừng nối vào cho tích hợp mới | **KHUNG** — chờ deploy validator `activation_vault` |
| Vault Wakeme — đọc | `GET /wakeme/vault/{did}` (bảng điều khiển 2 pha) · `GET /wakeme/pot` (sức khoẻ pot + D hiện tại). Bí danh cũ `/activation/*` vẫn bind | **KHUNG** — chờ deploy validator + Registry |
| ~~Activation cũ (luồng Genie)~~ | ~~`POST /activation/initiate` → `/activation/{id}/confirm-payment` → `/activation/{id}/submit-tx` · SSE `/activation/{id}/events` · `/status` · `/cancel`~~ | 🔴 **GỠ RỒI — đừng nối vào.** Dòng này từng ghi **READY**; sai kể từ **2026-09-03** (`PhoenixKey-Database/docs/VND-GENIE-REMOVAL.md`). Đo lại 2026-09-09: chỉ `ActivationVaultController` bind `/activation`, và nó **không** bind sáu đường này ⇒ **404**. SDK nay ném `PhoenixKeyError{code:"flow_retired"}` ngay, không đi mạng (SDK#9). Dùng **GetLAMP v5** ở dòng trên |
| Guardian recovery | `POST /guardians/add` · `/guardians/remove` (owner-signed) | **READY** |
| Khoá on-chain | `POST /keys/authorize` · `/keys/revoke` · `/keys/rotate` (trả txHash) | **READY** |
| Device recovery (Mode B) | `POST /identity/recover-device` (gắn HW key máy mới bằng TAAD_Key) | **READY** |
| Seed export | `POST /seed/export-request` (rotate-before-reveal) | **READY** |
| Sign-relay (web tạo intent, mobile ký) | `POST /sign/request` → `GET /sign/request/{id}` → `POST /sign/{id}/approve` (verify ECDSA + SSE trả sig) | **READY** |
| Config/health | `GET /health/cardano` (network, `lamp_policy_id`, hash+địa chỉ TAAD) · `GET /actuator/health` | **READY** |
| **JWKS** (verify JWT do PhoenixKey phát) | `GET /api/v1/.well-known/jwks.json` | **READY** — đo lại 2026-09-08 trên prod: **200** `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"phoenixkey-ed25519-1",…}]}`. Lỗi CORS trả 400 cho mọi client (kể cả server-to-server) đã vá: Database **PR #123 merge 2026-08-05**, mapping riêng `/.well-known/**` với `allowCredentials(false)` đăng ký TRƯỚC `/**` (`config/WebConfig.java`). ⚠ Còn lại **việc ops**: đường **gốc miền** `https://api.phoenixkey.me/.well-known/jwks.json` vẫn **404** vì `context-path=/api/v1` — RFC 8615 đòi ở gốc miền, cần nginx rewrite. Cho tới khi có rewrite, client phải trỏ thẳng đường `/api/v1/...`. **Bản trước của dòng này ghi "mặc định của `AppTokenVerifier` đã trỏ đúng" — SAI**: mặc định khi ấy là gốc miền trần, tức đúng đường 404. Đã vá cùng đợt 2026-09-08; nay mặc định thật sự trỏ đường có `/api/v1`, và có bài kiểm ghim chuỗi đó (`test/jwksUrl.test.ts`) |
| **Sinh MAGIC từ số dư LAMP** | `GET /wakeme/vault/{did}/magic` (MAGIC hằng ngày — **đọc số dư**, không đụng LAMP) · `GET /wakeme/gen-entry` (ranh giới engine Gen ↔ SDK MAGIC). Trường `magic` trong `GET /wallet/{did}/all` hiện trả 0 | **KHUNG** — chờ engine Gen bên MAGIC. Hai đường chính thống: **InstantGen** (tiêu ngay) + **ScheduleGen** (các epoch sau). Không có đường thứ ba |
| **Gửi ADA** (build/submit tx tổng quát) | `POST /wallet/tx/submit` — client dựng+ký CBOR local, backend relay lên chain (không state). Khác `/wakeme/submit` (gắn vault GetLAMP). Bản trước đối chiếu với `/activation/{id}/submit-tx` — đường đó **đã gỡ 2026-09-03**, nên phép đối chiếu cũ trỏ vào một thứ không còn | **READY** (Database PR #76 merge 2026-07-24) |
| **OrgDID uỷ-quyền thao tác LAMP** | `POST /identity/org/{orgDid}/mint-lamp` — OrgDID single-owner ký challenge → server phát **Grant** uỷ-quyền (`action` = `mint:LAMP`/`pot:fund`/`pot:distribute`). **KHÔNG đúc LAMP, KHÔNG submit tx** — chỉ verify chữ ký controller + phát Grant tự-verify (Anchorme §11.2). Xem mẫu §"Grant uỷ-quyền LAMP" | **READY** (Database PR #119 merge 2026-08-03) — nhưng phía TIÊU Grant chưa có, xem ghi chú cuối mục Grant |
| **Đúc/nạp LAMP thật (bên tiêu Grant)** | **KHÔNG phải endpoint PhoenixKey.** LAMP là 1 policy cố-định-36-tỷ, đúc một lần bởi kho phân phối (`dist_treasury`, thuộc **MagicLamp/LAMP**) — không có "mint LAMP theo từng OrgDID". `dist_treasury` **tiêu Grant ở trên** để ráp+ký+submit tx thật; PhoenixKey chỉ cấp OrgDID + uỷ-quyền. Tx đã ký relay qua `POST /wallet/tx/submit` | **ngoài phạm vi PhoenixKey** (→ LAMP) |
| **Pool — đọc** | `GET /pools?page=` · `GET /pools/{pool_id}` (số + metadata) · `GET /delegation/status/{stake_address}` (account chưa kích hoạt trả state đầy đủ, không 404) | **READY** (Database PR #77 merge 2026-07-24) |
| **Tạo pool / SPO — ký** | không có endpoint; mobile dựng + ký cert đăng ký pool (CIP-1852) rồi gửi qua `POST /wallet/tx/submit`. Backend không giữ khoá vận hành pool | **client-side** |
| Danh sách OrgDID | `GET /identity/org` **không tồn tại**. Chỉ có tạo (`/identity/org/create`, `/identity/org/founding`, `/identity/org/{orgDid}/upgrade-authority`) | **MISSING** — client tự giữ danh sách |
| **Claim LAMP theo ETD / Airdrop / SRCL** | không có route nào (`/airdrop-claim/...` trả 404). Cơ chế Merkle + tham số đợt phát thuộc **LAMP**, không phải PhoenixKey | **MISSING** — chờ chốt ranh giới với LAMP |
| Tên người dùng, thiết bị, nhật ký, hỗ trợ | `POST /identity/username` · `GET /identity/by-username/{username}` · `GET /identity/nodes` · `POST /devices/register` · `GET /activity-logs` · `POST /support/session/init` · `POST /tx/estimate` | **READY** (`/tx/estimate` trả phí cố định 200.000 lovelace, chưa ước lượng thật) |
| ⚠ Tàn dư mô hình cũ — **đừng nối vào** | `POST /wallet/magic/claim` luôn trả **410 Gone** (MAGIC không đúc, không claim). `POST /wakeme/getmagic/{quote,checkout}` + `GET /wakeme/getmagic/{orderId}` (bí danh cũ `/activation/getmagic/*`) là mua **CARP** bằng tiền pháp định — tên "GetMAGIC" là nhầm lẫn còn sót | **đang dọn** |

### ⚠ Quy ước đặt tên TRÊN DÂY — `snake_case`, không phải `camelCase`

**Đọc mục này trước khi viết bất kỳ client nào.** Backend đặt `spring.jackson.property-naming-strategy: SNAKE_CASE` toàn cục (`PhoenixKey-Database/src/main/resources/application.yml:9`). Java record giữ `camelCase` trong mã, Jackson convert khi (de)serialize. Nên **tên trên dây luôn là `snake_case`**: `owner_did`, `owner_signature`, `amount_lamp`, `valid_ttl_seconds`, `grantee_did`, `registration_number`, `tx_hash`, `org_did`.

Lỗi này ngấm ngầm vì trường **một từ** (`action`, `resource`, `nonce`, `name`) thì snake == camel nên bind bình thường. Chỉ trường **nhiều từ** rơi lặng lẽ, rồi `@NotBlank` báo "required" cho đúng trường client tin là đã gửi. Đo thật 2026-08-05, cùng một thân yêu cầu chỉ khác cách đặt tên:

```
# camelCase
POST /api/v1/identity/org/{orgDid}/mint-lamp   {"amountLamp":"…","ownerDid":"…","ownerSignature":"…", …}
→ 400 {"code":9800,"message":"amountLamp: amountLamp is required; ownerDid: ownerDid is required; …"}

# snake_case
POST /api/v1/identity/org/{orgDid}/mint-lamp   {"amount_lamp":"…","owner_did":"…","owner_signature":"…", …}
→ 404 {"code":2002,"message":"OrgDID not found: …"}     ← đã qua validation, tới bước tra DB
```

Hai ngoại lệ **giữ camelCase** vì chuẩn ngoài quy định: **W3C DID Document** (`GET /identity/{did}/document`) và **JWKS** RFC 7517 (`GET /.well-known/jwks.json`) — cả hai mang `@JsonNaming(LowerCamelCaseStrategy)` riêng.

> `GET /api/v1/v3/api-docs` (springdoc) **công bố camelCase — sai**: springdoc không áp naming strategy. Đừng sinh client từ nó mà không đổi tên. Mục này là nguồn đúng.

### Mẫu OrgDID — `POST /identity/org/create` (single-owner)

Đường **`/identity/org/create`** (KHÔNG phải `/identity/org` trơn — bản đó trả 404). Owner ký challenge canonical bằng HW_Key đang active của `owner_did`.

```
POST /api/v1/identity/org/create
Content-Type: application/json
{
  "owner_did": "did:phoenix:<b32-13>:<hex-64>",   // PersonDID sở hữu, phải đã register
  "name": "Công ty TNHH ABC",                      // 1–100 ký tự, KHÔNG cần duy nhất
  "registration_number": "0312345678",             // tuỳ chọn (MST); "" nếu không có
  "owner_signature": "<hex>",                      // ECDSA/Ed25519 ký challenge dưới
  "nonce": "<1–64 ký tự>"                          // dùng-1-lần theo (owner_did,nonce)
}

challenge = "PHOENIXKEY_ORG_MINT:" + owner_did + ":" + name + ":" + (registration_number||"") + ":" + nonce
// UTF-8 thô, phân cách bằng ":" trần, KHÔNG băm ở tầng ứng dụng (băm 0 lần — ECDSA/Ed25519 tự băm bên trong).
// name tiếng Việt giữ nguyên UTF-8, không NFC/NFD, không percent-encode.

200 → { "code":1000, "message":"Org minted",
        "result": { "org_did":"did:phoenix:...", "owner_did":"did:phoenix:...", "tx_hash":"<hex>" } }
400 code 9800 thiếu field · 403 chữ ký owner sai · 404 owner_did chưa register · 409 nonce đã dùng
```

`tx_hash` hiện là tx publish metadata-6789 (chuyển sang TAAD-UTxO-mint khi validator OrgDID deploy). `m-of-n`: `POST /identity/org/founding`; nâng single→threshold: `POST /identity/org/{orgDid}/upgrade-authority`.

### Grant uỷ-quyền LAMP — `POST /identity/org/{orgDid}/mint-lamp`

Nghĩa: OrgDID (GreenSun) là **danh tính ký/uỷ quyền** cho thao tác LAMP treasury/pot — **KHÔNG đúc token**. Endpoint verify controller của OrgDID đã ký, rồi phát **Grant** tự-verify (Anchorme §11.2). `dist_treasury` (MagicLamp) tiêu Grant để ráp+ký+submit tx thật. LAMP giữ cung cố-định 36 tỷ.

```
POST /api/v1/identity/org/{orgDid}/mint-lamp
Content-Type: application/json
{
  "action": "mint:LAMP",              // mint:LAMP | pot:fund | pot:distribute
  "resource": "<pot-id / addr kho>",  // đích của action (≤200 ký tự), opaque với backend
  "amount_lamp": "26000000000000000", // oildrop (đơn-vị-nhỏ-nhất) — CHUỖI big-number
  "grantee_did": "did:phoenix:...",   // tuỳ chọn: bên được uỷ quyền thực thi (vd operator dist_treasury)
  "valid_ttl_seconds": 3600,          // tuỳ chọn, 60–604800: HẠN theo GIÂY (client KHÔNG cần đồng hồ slot)
  "owner_did": "did:phoenix:...",     // controller single-owner của org_did (phải == owner của org)
  "owner_signature": "<hex>",         // ký challenge dưới, bằng HW_Key ĐANG ACTIVE của owner_did
  "nonce": "<1–64 ký tự>"             // dùng-1-lần theo (owner_did,nonce)
}

challenge = "PHOENIXKEY_ORG_LAMP:" + org_did + ":" + action + ":" + amount_lamp + ":"
          + resource + ":" + (grantee_did||"") + ":" + (valid_ttl_seconds||"") + ":" + nonce
// ⚠ amount_lamp đứng TRƯỚC resource — ngược thứ tự khai báo trong thân yêu cầu. Dựng xuôi từ giá trị,
//   đừng tách ngược chuỗi challenge.
// Server tự tính valid_from_slot = tip hiện tại, valid_until_slot = valid_from_slot + valid_ttl_seconds (≈1 slot/s).

200 → { "code":1000, "message":"LAMP authorization grant issued",
        "result": { "grant_id":"<uuid>", "grantor_did":"<org_did>", "grantee_did":..., "action":"mint:LAMP",
                    "resource":..., "amount_lamp":"26000000000000000", "valid_from_slot":..., "valid_until_slot":...,
                    "nonce":..., "status":"ISSUED", "signer_did":..., "signer_public_key_hex":"<hex>",
                    "signature":"<hex>", "canonical_challenge":"PHOENIXKEY_ORG_LAMP:...", "revocable":true } }
403 chữ ký sai / signer không phải controller · 404 org_did không tồn tại · 409 nonce đã dùng · 409 org không single-owner (m-of-n chưa hỗ trợ) · 400 valid_until_slot đã quá hạn
```

`dist_treasury` xác minh Grant bằng cách re-verify `signature` trên `canonical_challenge` với `signer_public_key_hex` (controller HIỆN-TẠI của `grantor_did`) + còn hạn + chưa thu-hồi. `amount_lamp` là CHUỖI oildrop — parse bằng `BigInt`.

**Grant là năng lực dạng bearer.** Cất Enclave/Keychain, KHÔNG AsyncStorage.

> 🔴 **ĐÍNH CHÍNH 2026-08-10 — bản trước của mục này hứa một thứ không có gì đỡ.**
>
> Bản trước viết: *"luôn đặt `grantee_did` = DID của operator `dist_treasury`. Đặt rồi thì lộ Grant không còn tự động thành mất tiền."* **Sai.** Đặt `grantee_did` hiện KHÔNG đổi gì về mức rủi ro, vì không có chỗ nào kiểm nó:
>
> - **On-chain: không kiểm, và không kiểm được.** `dist_treasury` nhận đúng MỘT tham số `authority` (pkh) và toàn bộ thân spend là một dòng — `list.has(self.extra_signatories, authority)`. Nó không đọc datum, không đọc redeemer, và **không bao giờ nhìn thấy `grantee_did`**. Ai giữ khoá `authority` thì rút được, có Grant hay không, `grantee_did` điền hay để trống.
> - **Backend: cũng không kiểm.** `granteeDid` được kiểm ĐỊNH DẠNG lúc phát (`OrgLampGrantRequest.java:68`), vào `canonical_challenge` ở vị trí thứ sáu (`OrgServiceImpl.java:385`), và lưu vào `OrgLampGrant.java:44`. Không có bên nào ĐỌC nó ra để so. Vì phía tiêu Grant chưa tồn tại (xem khối dưới), chưa có bên kiểm nào để mà kiểm.
>
> ⟹ **`grantee_did` hôm nay là một trường ghi-vào-sổ, không phải một cổng.** Nó ràng buộc chữ ký (đổi giá trị là đổi challenge là hỏng chữ ký), nhưng nó không ràng buộc **ai tiêu được**.
>
> **Vẫn nên điền**, vì hai lý do thật: (a) nó vào `canonical_challenge` nên nó ghi lại **ý định** của bên phát, dùng được cho đối soát và cho phía tiêu sau này; (b) khi phía tiêu ra đời, Grant đã phát mà bỏ trống thì không hồi tố siết được. Nhưng **đừng coi việc điền là một biện pháp giảm hại đang có hiệu lực** — biện pháp duy nhất đang có hiệu lực là cất kỹ.
>
> Để trống hợp lệ đúng một ca: lúc phát chưa biết operator là DID nào. Đó là **ngoại lệ có điều kiện**, không phải "tuỳ chọn".

> **Phía TIÊU Grant chưa tồn tại — đọc trước khi lên lịch.** Trên `main` không có mã nào chuyển `status` khỏi `ISSUED`: không endpoint consume, không revoke, không tra cứu. `revocable: true` hiện là lời hứa chưa có cơ chế. Nghĩa là dựng luồng **lấy** Grant là đúng thứ tự và không phải làm lại — nhưng lấy được Grant KHÔNG có nghĩa LAMP chảy.

### Hợp đồng số lớn — số lượng on-chain là JSON _string_

Tổng cung LAMP = 3,6×10¹⁶ oildrop > `Number.MAX_SAFE_INTEGER` (9,007×10¹⁵). Vì vậy các trường **số lượng đơn-vị-nhỏ-nhất** (`balances.{lovelace,lamp,carp}`, `magic.{available,accrued}`, `amount_lamp`/`amount_lovelace`, `d_oildrop`, `pot_balance_lamp`) serialize thành **chuỗi**, không phải number — để `JSON.parse` không mất chữ số ở ví/kho lớn. Client parse bằng `BigInt`/`bigint`. Trường **slot/ngày/phase/đếm** vẫn là number. (Đổi này: Database PR #102, đã merge 2026-07-30.)

> **Prod ĐANG SỐNG.** Base URL `https://api.phoenixkey.me/api/v1` — mọi route nằm dưới context-path `/api/v1`; gốc `https://api.phoenixkey.me/` trả 404 là **đúng hành vi**, không phải sự cố. Điểm kiểm nhanh:
>
> ```
> GET https://api.phoenixkey.me/api/v1/actuator/health   → 200 {"status":"UP"}
> GET https://api.phoenixkey.me/api/v1/health/cardano    → 200
>      Swagger  https://api.phoenixkey.me/api/v1/swagger-ui.html
> ```
>
> ⚠ **Số đo 2026-08-04, CHƯA đo lại — và giá trị `lamp_policy_id` bên dưới nay đã bị tuyên chết.** `5e83cd3e…` là `lamp_policy` V1: `mint_authorized` mở nhánh burn cho bất kỳ ai, trái bất biến "LAMP cố định 36 tỷ, KHÔNG burn", nên nó nằm trong danh sách cấm của đường deploy. Nếu `/health/cardano` hôm nay còn trả giá trị đó thì đó là **lỗi cấu hình đang chạy**, không phải một giá trị dùng được — số dư LAMP đọc qua nó sẽ luôn ra 0, im lặng. Đo lại trước khi tin: `curl -s <host>/api/v1/health/cardano`. Đừng lấy `lamp_policy_id` từ đây làm policy của **token** — xem §5, hai thứ khác nhau.
>
> Nguyên văn số đo cũ, giữ để tra: `/health/cardano` trả đủ `lamp_policy_id` = `5e83cd3e9c9e66dc989e64626dde2aa23be552f8a08485398137352a`, `taad_script_hash` = `f8d8bb57ff472d1c7269ec00a31444bfae82c5d045977787e4c589b9`, `taad_script_address` = `addr_test1wrud3w6hlarj68rjd8kqpgc5gjl6aqk96pzewau8unzcnwg8sn0ql`, `taad_script_cbor_hex` (19548 ký tự), và `taad_script_hash_history` (2 hash cũ). Client đối chiếu **policy-id** fail-closed nay hoạt động được — trước đây trường rỗng làm LAMP thật cũng bị chặn.
>
> `magic_policy_id` rỗng là **đúng theo thiết kế** — MAGIC là tài khoản trong vault, không có policy-id. Client KHÔNG được coi trường rỗng này là lỗi cấu hình.
>
> **JWKS — lỗi 400 đã vá, chỉ còn việc ops.** Số đo thô 2026-09-08 trên prod:
>
> ```
> GET https://api.phoenixkey.me/api/v1/.well-known/jwks.json → 200
>     {"keys":[{"kty":"OKP","crv":"Ed25519","x":"…","use":"sig","alg":"EdDSA","kid":"phoenixkey-ed25519-1"}]}
> GET https://api.phoenixkey.me/.well-known/jwks.json         → 404
> ```
>
> Phần **400** (CORS — `allowCredentials=true` không đi cùng `allowedOrigins="*"`,
> chặn cả gọi server-to-server) ĐÃ LỖI THỜI, vá ở Database **PR #123 merge
> 2026-08-05**. Phần còn đúng: đường **gốc miền** vẫn trả **404** vì
> `context-path=/api/v1`, RFC 8615 thì muốn `.well-known` ở gốc — cần nginx
> rewrite, việc ops, chưa làm. Client lấy khoá công khai issuer qua
> `GET /api/v1/.well-known/jwks.json`, và đó là mặc định của `AppTokenVerifier`
> kể từ đợt 2026-09-08 (trước đó mặc định trỏ gốc miền trần, tức đúng đường 404).

> **On-chain (tham chiếu):** 2-of-2 `controller_pkh ∧ device_pkh` đã canonical trong validator (`auth_logic.ak`, 463 test PASS) nhưng CHƯA re-apply vào deploy artifact — anchor/ví đang live là bản 1-of-1 cũ. `did_payment`/`did_stake`/`limit_meter_vault`/`activation_vault` compile+test xanh, phần lớn BUILT chưa deploy. Chỉ TAAD có UTxO thật trên Preview.

## 3. Identity & Data compliance (§3)

- **§3.1 DID root**: PhoenixKey DID = root danh tính; module khác KHÔNG redefine, chỉ tiêu thụ qua service API. Issuer-side EdDSA + `/.well-known/jwks.json` thuộc **đội backend** (Claude KHÔNG sửa PhoenixKey backend).
- **§3.2 INV-1**: store DID = single source of truth; mọi client (kể cả app native) ghi qua fabric API versioned + idempotency key. Client KHÔNG ghi data layer trực tiếp.
- **§3.4 INV-3**: on-chain (TAAD anchor) CHỈ chứa **hash/commitment/pointer** — KHÔNG PII/sinh trắc raw. PII + sinh trắc off-chain, store tại VN, erasable. Consent per-host. Capability cưỡng chế qua broker.
- **LoA (§3.1)**: chỉ DID sinh trắc gốc có quyền governance; DID liên kết host ngoài (LoA thấp) chỉ dùng tính năng.

## 4. Embed / kênh 3 (§5) — federation danh tính

- Bằng chứng danh tính sinh + ký TRONG app PhoenixKey gốc (Secure Enclave) hoặc QR challenge-response. **DID gốc/sinh trắc KHÔNG BAO GIỜ vào WebView host.**
- **Chuẩn (§5.1) đòi** token host nhận là **audience-bound + sender-constrained (DPoP), sống-ngắn**.
  Đây là mục tiêu của §5.1, **KHÔNG phải hiện trạng** — xem sửa ở mục 6 bên dưới.
- **Issuer-side mint EdDSA + JWKS: ĐÃ XONG** (`JwksController` live trên `main` PhoenixKey-Database từ trước nhánh này — `GET /api/v1/.well-known/jwks.json`, verify được qua `AppTokenVerifier` ở `src/verifier.ts`, test PASS). Dòng "blocker thuộc đội backend" ở bản trước ĐÃ LỖI THỜI — gỡ. **Blocker còn lại của kênh 3 là sender-constrained (DPoP)**, xem mục 6.

### 4.1 Đổi thẻ phiên lấy thẻ app — `client.auth.exchange()`

**Đừng đưa `session_token` cho app đối tác.** Đó là thẻ toàn quyền của người dùng, sống **24 giờ**: nó mở mọi endpoint của người đó — đọc ví, tạo yêu cầu ký, đổi tên và thu hồi thiết bị. Trao nó đi là trao trọn tài khoản trong một ngày, và không có đường thu lại ngoài việc bắt người dùng đăng nhập lại toàn hệ.

Thứ được trao đi phải là **`app_token`**: ràng vào **đúng một `aud`** (ServiceDID của app đích) và sống **15 phút** (`PHOENIXKEY_SSO_APP_TOKEN_TTL`, mặc định `15m`). App nhận không dùng nó ở nơi khác được, và nó tự chết rất nhanh.

```ts
const { appToken, expiresIn } = await client.auth.exchange({
  sessionToken: client.session.getSessionToken()!,
  aud: "did:phoenix:<b32-13>:<hex-64>",      // ServiceDID app đích, KHÔNG phải tên miền
  redirectUri: "https://partner.example/callback",
  // nonce: "…"                              // tuỳ chọn, ≤ 64 ký tự, chép vào claim `nonce`
});
```

Phía app đích verify bằng `AppTokenVerifier` (`@phoenixkeydid/phoenixkey-sdk/verifier`) — chữ ký Ed25519 theo JWKS, hạn dùng, và `aud`.

**Bốn điều dễ sai:**

1. **`redirect_uri` so khớp NGUYÊN CHUỖI** với một phần tử trong `serviceEndpoint[]` của DID Document thuộc `aud`. Máy chủ không chuẩn hoá — thừa/thiếu dấu `/` cuối là trượt. Sai ở đây trả `redirect_uri_mismatch` (400), là lỗi **cấu hình app đích**, không phải lỗi người dùng: cho đăng nhập lại không cứu được gì.
2. **Đừng viết cứng 900 giây.** Dùng `expiresIn` trả về. SDK đọc nó từ trường `expires_in` nếu máy chủ gửi, ngược lại từ claim `exp` mà chính máy chủ đã ký trong thẻ. Viết cứng thì ngày máy chủ đổi TTL, phía tích hợp hết hạn sai lúc mà không có gì báo.
3. **`session_token` đi trong THÂN yêu cầu POST**, không bao giờ trong chuỗi truy vấn. Tham số URL nằm lại trong lịch sử trình duyệt, trong header `Referer` gửi sang trang khác, và trong log truy cập của mọi proxy trên đường. `exchange()` chốt điều này bằng một bài kiểm.
4. **Có hạn mức lượt đổi trên mỗi `session_token`** (`rate_limited`, 429) — đổi khi cần, đừng đổi trong vòng lặp.

Mã lỗi phân biệt được, đều là `PhoenixKeyError`: `unauthorized` (401 — phiên chết/khoá bị thu hồi → đăng nhập lại) · `signature_invalid` (403 — thẻ hỏng/hết hạn) · `redirect_uri_mismatch` (400) · `service_did_not_found` (404 — `aud` chưa công bố endpoint nào) · `rate_limited` (429) · `enum_invalid_value` (400 — `aud` sai khuôn `did:phoenix:…`, `nonce` quá 64 ký tự).

> ⚠ **`app_token` là thẻ mang-là-dùng (bearer).** Chưa có ràng buộc sở-hữu-khoá (DPoP) — xem mục 6. Ai cầm được chuỗi thẻ thì dùng được thẻ, nguyên vẹn tới `exp`, không cần chứng minh gì thêm. Nên: **không ghi vào log**, không đặt vào URL, không cất `localStorage` — giữ trong bộ nhớ tiến trình, và xin thẻ mới thay vì kéo dài một thẻ.

### 4.2 Nối một trang web bên thứ ba — vòng đầy đủ

Năng lực: người dùng mở trang của bạn, quét QR bằng app PhoenixKey, duyệt bằng
sinh trắc, và trang của bạn có phiên — không mật khẩu, không chạm tới seed.

Bốn mắt, ba mắt nằm ở phía bạn:

```ts
// ── 1. Trang của bạn: đẩy người dùng sang PhoenixKey ────────────────────────
import { buildLoginUrl, createHandoffState } from "@phoenixkeydid/phoenixkey-sdk";

const state = createHandoffState();
sessionStorage.setItem("pk_state", state);
location.assign(buildLoginUrl({
  redirectUri: "https://app.cua-ban.com/callback",   // NGUYÊN VĂN, xem ràng buộc dưới
  state,
}));

// ── 2. phoenixkey.me lo phần giữa ───────────────────────────────────────────
//     init phiên → QR → điện thoại duyệt → SSE báo về → trang đăng nhập đổi
//     `session_token` lấy `app_token` rồi mới chuyển hướng. `session_token`
//     KHÔNG rời trang đăng nhập; chỉ `app_token` đi vào fragment URL của bạn.

// ── 3. Trang /callback của bạn: nhận, và XOÁ khỏi thanh địa chỉ ─────────────
import { consumeHandoff } from "@phoenixkeydid/phoenixkey-sdk";

const handoff = consumeHandoff({
  expectedState: sessionStorage.getItem("pk_state") ?? undefined,
});
if (handoff) {
  sessionStorage.removeItem("pk_state");
  await fetch("/api/dang-nhap", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ app_token: handoff.appToken }),   // sang MÁY CHỦ của bạn
  });
}

// ── 4. MÁY CHỦ của bạn kiểm thẻ, rồi mới tin ────────────────────────────────
import { AppTokenVerifier } from "@phoenixkeydid/phoenixkey-sdk/verifier";

const claims = await new AppTokenVerifier().verify(appToken, MY_SERVICE_DID);
// claims.sub = DID người dùng. ĐÂY mới là nguồn đáng tin — không phải
// `handoff.userDid`, thứ chưa có chữ ký nào bảo vệ.
```

> **⚠ Đổi từ 0.7.0 — phá vỡ tương thích.** Tham số thứ hai (`MY_SERVICE_DID`)
> nay **bắt buộc**. Trước đó nó tuỳ chọn, và bỏ quên là tắt luôn phép kiểm
> `aud` mà không có cảnh báo nào — trình biên dịch im, thời gian chạy im.
>
> Vì sao điều đó nguy hiểm: một thẻ được đúc cho **một** dịch vụ. Không kiểm
> `aud`, máy chủ của bạn nhận cả thẻ đúc cho dịch vụ khác. Kẻ tấn công dựng
> một dịch vụ của chính nó, dụ người dùng đăng nhập vào đó, rồi mang thẻ thu
> được sang máy chủ của bạn — và đăng nhập với tư cách người dùng đó.
>
> Nâng cấp: truyền ServiceDID của bạn. Nếu bạn thật sự có ràng buộc khác thay
> thế và muốn bỏ phép kiểm, gọi `verifyWithoutAudience(appToken)` — đặt tên
> như vậy để người đọc chỗ gọi nhìn thấy phép kiểm đang tắt, thay vì phải đoán
> từ một tham số vắng mặt.

**Điều kiện tiên quyết, sai là trượt với `redirect_uri_mismatch` (400):**

1. `redirectUri` phải khớp **nguyên chuỗi** một phần tử trong `serviceEndpoint[]`
   của DID Document thuộc ServiceDID của bạn. Máy chủ so chuỗi, không chuẩn
   hoá — thừa hay thiếu một dấu `/` cuối là trượt. Khai bằng
   `POST /identity/{did}/services` (Bearer của chính DID đó).
2. Origin của bạn phải nằm trong `NEXT_PUBLIC_ALLOWED_REDIRECT_ORIGINS` của bản
   dựng phoenixkey.me, theo văn phạm `origin=ServiceDID`. Đây là cấu hình lúc
   dựng phía PhoenixKey, không phải thứ máy khách khai được — nếu máy khách
   khai được `aud` thì cổng đối chiếu `serviceEndpoint[]` ở máy chủ mất hết ý
   nghĩa. **Chưa được khai thì người dùng đăng nhập xong sẽ nằm lại ở
   `/dashboard` của phoenixkey.me, và trang của bạn không nhận được gì** — im
   lặng, không có thông báo lỗi nào. Liên hệ đội PhoenixKey để thêm origin.

**Ba điều `src/sso.ts` giữ, và đừng gỡ:**

- Thẻ chỉ đọc từ **fragment**, không bao giờ từ chuỗi truy vấn. Query đi vào
  `Referer`, log proxy, log truy cập; fragment thì không rời trình duyệt.
- Fragment mang `session_token` / `linked_device_token` / `temp_token` ⇒ **ném**.
  Đó là thẻ rộng hơn `app_token` rất nhiều; gặp chúng nghĩa là máy chủ đầu kia
  đang chạy bản cũ. Nhận bừa là mang lỗ hổng của họ về nhà mình.
- `consumeHandoff` **xoá fragment** bằng `history.replaceState` ngay sau khi
  đọc — kể cả khi lượt bàn giao bị từ chối. Không xoá thì `app_token` nằm lại
  trong lịch sử trình duyệt, và nó là thẻ mang-là-dùng.

Bài kiểm ghim cả ba: `test/sso.test.ts` (có bảng đột biến ở cuối tệp). Bước 4 dùng
đúng `AppTokenVerifier` nói ở §4.1 bên trên.

## 5. Anchor on-chain đã deploy, và định danh token theo mạng

Deploy tx: `b22bc2077bd3e91d306faa6324d70083701b7d0ebda43e40e1a6943a9dc16c5b` (verify Blockfrost hash-at-index).
- `TAAD_ANCHOR_POLICY_ID` = `0f665f9967e5b735949e4def618b6b56cff9e18f0f74571303f49a3f`
- ⛔ `lamp_policy` (validator) = ~~`f1884536db71ba734e94d4aa451376d45fa49c24f03caaf1e5165408`~~ — **ĐÃ CHẾT, đừng dùng.** Dòng này từng ghi kèm chữ "(không đổi)" và chữ đó sai từ commit `82e9dcf` (2026-07-16). Đời kế của nó (`5e83cd3e…`) **cũng chết và bị cấm**: `mint_authorized` mở nhánh burn cho bất kỳ ai, trái bất biến "LAMP cố định 36 tỷ, KHÔNG burn" — nên cả module `lamp_policy` đã ra khỏi đường deploy từ 2026-09-14. Ai còn ghim một trong hai giá trị này sẽ đọc ra số dư 0 hoặc dựng giao dịch cho một tài sản không tồn tại — **hỏng dưới dạng "không thấy tiền", không phải dưới dạng lỗi**, nên không ai được cảnh báo. ⚠ Tên biến `LAMP_POLICY_ID` trong các tệp cấu hình mẫu trỏ tới **policy của TOKEN** (mục dưới), không phải hash validator này — hai thứ khác nhau mang tên gần giống.
- **tLAMP / LAMP token** — ⚠ **Không mạng nào ở đây cho bạn một giá trị vĩnh viễn, kể cả mainnet.** Đọc hết mục này trước khi viết dòng mã đầu tiên.

  Bản trước của dòng này ghi `7a1a7aed5ec47acc37b6fa82695c1219bf76895b505b01161367adf9` là *"canonical cả Preview+Preprod"*. **Câu đó sai ở cả hai mạng.** Đối chiếu sổ policy — kho công khai, ai cũng mở được: [`lampPolicies.ts:127`](https://github.com/MagicLampEco/LAMP/blob/1ef32ee0b168147781ef01dfd68cb1a01cf32623/Genesis/offchain/src/lampPolicies.ts#L127) và [`:235`](https://github.com/MagicLampEco/LAMP/blob/1ef32ee0b168147781ef01dfd68cb1a01cf32623/Genesis/offchain/src/lampPolicies.ts#L235) đều ghi `status: "SUPERSEDED"`. Nếu bạn đã chép giá trị đó, nó đang trỏ vào một đời token đã bị thay.

  ### Nguồn quyền uy — dùng cái này, đừng dùng bảng dưới

  Sổ policy là **nguồn duy nhất**. Nó công khai, đọc được không cần tài khoản:

  - Kho: [`MagicLampEco/LAMP`](https://github.com/MagicLampEco/LAMP) · tệp [`Genesis/offchain/src/lampPolicies.ts`](https://github.com/MagicLampEco/LAMP/blob/1ef32ee0b168147781ef01dfd68cb1a01cf32623/Genesis/offchain/src/lampPolicies.ts)
  - Hàm cần gọi: `activeLampPolicyId(network)` — nó **ném** nếu mạng đó chưa có bản `ACTIVE`, thay vì trả một giá trị trông hợp lệ.
  - Đối chiếu nhanh không cần clone:
    ```bash
    curl -s https://raw.githubusercontent.com/MagicLampEco/LAMP/main/Genesis/offchain/src/lampPolicies.ts | grep -n 'policyId\|status'
    ```

  Bảng dưới là **bản chép**, đo tại commit [`1ef32ee0`](https://github.com/MagicLampEco/LAMP/commit/1ef32ee0b168147781ef01dfd68cb1a01cf32623) ngày 2026-09-20. Bản chép thì trôi — nếu nó lệch với sổ, **sổ đúng**.

  | mạng | policy id | tên tài sản | trạng thái |
  |---|---|---|---|
  | Preprod | `8169b76cdaba83cf7c9ae32ebd2bb3a58aa215c7dc0b62c8f5e268dd` | `744c414d50` | [`ACTIVE`](https://github.com/MagicLampEco/LAMP/blob/1ef32ee0b168147781ef01dfd68cb1a01cf32623/Genesis/offchain/src/lampPolicies.ts#L184) — **tạm thời**, xem dưới |
  | Preview | `7a1a7aed5ec47acc37b6fa82695c1219bf76895b505b01161367adf9` | `744c414d50` | [`SUPERSEDED`](https://github.com/MagicLampEco/LAMP/blob/1ef32ee0b168147781ef01dfd68cb1a01cf32623/Genesis/offchain/src/lampPolicies.ts#L235) — đời thay còn [`PENDING-MINT`](https://github.com/MagicLampEco/LAMP/blob/1ef32ee0b168147781ef01dfd68cb1a01cf32623/Genesis/offchain/src/lampPolicies.ts#L258) |
  | Mainnet | `55d3e01bb6c469e02665e4b6573ce65bbaf7a50ad2024e247eb180f0` | **`4c414d50`** ⚠ khác testnet | `ACTIVE` — nhưng là [**bản MỒI sẽ bị thay**](https://github.com/MagicLampEco/LAMP/blob/1ef32ee0b168147781ef01dfd68cb1a01cf32623/Genesis/offchain/src/lampPolicies.ts#L116) |

  ⚠ **`ACTIVE` ở đây KHÔNG nghĩa là ổn định.** Nó chỉ nghĩa là "bản đang dùng của mạng này, hôm nay". Preprod đã đi qua **ba** đời policy id và hai đời đầu đều đã `SUPERSEDED`. Và bản ghi mainnet tự khai nguyên văn: *"Bản MỒI. Sẽ bị thay bởi policy uỷ quyền OrgDID — policy id SẼ KHÁC. Đừng nhúng cứng."* Không có mạng nào miễn trừ.

  ### ĐỌC thì được, NƯỚNG thì không — phân biệt này quyết định bạn có mất tiền hay không

  Hai cách dùng một policy id, hậu quả khác nhau hoàn toàn:

  - **ĐỌC** (lọc số dư, dựng tx chuyển) — đọc từ cấu hình lúc chạy. Policy đổi thì bạn sửa một biến môi trường và xong.
  - **NƯỚNG vào apply-param** của một validator (escrow, vault, khoá LAMP) — giá trị đi thẳng vào **script hash**, tức vào **địa chỉ**. Policy đổi thì địa chỉ đã tạo đóng băng: **không đường di trú tự động, không dòng lỗi nào lúc deploy**. Và LAMP **không burn** — tài sản rót vào một policy không ai giữ thì không ai lấy lại được.

  Đọc policy id từ biến môi trường rồi truyền chính biến đó vào `applyParamsToScript` **không phải là tuân thủ** — giá trị vẫn bị đông cứng. Nếu thiết kế của bạn cần nướng, hãy nướng một giá trị mà bạn kiểm soát vòng đời, đừng nướng giá trị này.

  ### Bốn bước lọc tài sản — thiếu bước nào cũng nhận nhầm

  Không có "token LAMP" theo tên. Chỉ có **đúng một cặp** được nhận, mỗi mạng một cặp:

  1. **Ghép trọn `unit`.** Blockfrost/Koios trả `unit = policy_id ‖ asset_name` **nối liền**, không tách hai trường. So trọn chuỗi đó. Đừng dùng `endsWith(assetName)` — nó khớp mọi policy.
  2. **Dùng hex, không dùng tên hiển thị.** `744c414d50` là hex của `tLAMP`, `4c414d50` là hex của `LAMP`. Nhiều API trả kèm trường tên đã giải mã — đừng so với trường đó.
  3. **Chuẩn hoá** `trim().toLowerCase()` cả hai vế trước khi so.
  4. **Fail-closed khi cấu hình rỗng.** `policyId ?? ""` ghép với asset name ra một `unit` trông hợp lệ và khớp nhầm. Thiếu biến thì **dừng và báo lỗi**, đừng chạy tiếp với chuỗi rỗng.

  Áp cả bốn bước cho **đầu ra** nữa — địa chỉ nhận và tiền thừa của tx bạn dựng — không chỉ cho bộ lọc đầu vào.

  Đây là **danh sách trắng một phần tử**, không phải danh sách đen. Đừng viết `if (biếtLàGiả) reject` — đúc một token trùng tên tốn khoảng 2 ADA và không cần quyền gì, nên tập cần chặn là vô hạn còn tập được nhận thì đúng một.

  ### Ba điều dễ hiểu nhầm

  - **Một policy id có thể xuất hiện trên hai mạng cùng lúc.** `7a1a7aed…` nằm ở cả Preview lẫn Preprod. Lý do: policy đó được dẫn ra từ chữ ký của ví triển khai, mà cùng một ví thì ký ở mạng nào cũng cho cùng kết quả. Hệ quả cho bạn: **policy id không phải là dấu hiệu phân biệt mạng**. Nếu đồ gá kiểm thử của bạn dựa vào nó để biết đang ở mạng nào, nó sẽ chạy chéo mạng mà không có gì báo.
  - **Token Preview bạn lấy từ faucet thuộc đời `SUPERSEDED`, và nó KHÔNG có trần cưỡng chế được.** Faucet Preview vẫn đang nhả token, nên "mắt thấy có token" không mâu thuẫn với "sổ ghi SUPERSEDED". Đời đó neo marker bằng chữ ký ví chứ không one-shot ⇒ người giữ khoá dựng lại được trạng thái cung với bộ đếm về 0 và đúc lại trọn hạn mức, hợp lệ theo đúng validator. Con số cung của nó là **lời hứa vận hành, không phải ràng buộc của chuỗi**. Dùng để thử luồng thì được; đừng để nó thành nguồn giá trị trong sản phẩm.
  - **Đơn vị.** `1 LAMP = 10⁶ oildrop`. Mọi số lượng trên chuỗi là oildrop. Đối chiếu một con số cung với "36 tỷ" mà quên đổi đơn vị sẽ lệch đúng 10⁶ và dẫn bạn tới kết luận sai về token nào là thật.

  Và cái bẫy ngược: một con số cung **khớp đúng** hạn mức cũng không chứng minh gì — ít nhất một policy trùng tên đang mang đúng con số đó. Chỉ cặp `(policy_id, asset_name)` mới quyết định.

Giao dịch minh hoạ khác: Wakeme 1001 tLAMP Preview `01139ba8af1f7556b70a82126aff7fd1b940bc8157c973b45e019e27c7870f16` — ⚠ đọc như **bằng chứng luồng Wakeme từng chạy**, đừng đọc như khuôn mẫu để chép: nó tiêu đời tLAMP Preview nay đã `SUPERSEDED`, đời mà bảng trên dặn đừng lấy làm nguồn giá trị.

## 6. Checklist tuân thủ (§8) — trạng thái PhoenixKey (silent)

**Manifest & Config**
- [x] Manifest silent hợp lệ; `capabilities` tối thiểu; `mergePolicy` khai rõ. `config.schema.json` declarative — chờ hoàn thiện.
- [ ] Static capability scan ở Registry — chờ Registry.

**Identity & Data**
- [x] Ghi data qua fabric API + idempotency (INV-1). On-chain chỉ hash/commitment (TAAD anchor) (INV-3). Consent per-host + broker default-deny.

**Embed (kênh 3)**
- [x] Credential/biometric KHÔNG vào WebView (DID gốc/sinh trắc chỉ sống trong Secure Enclave / app gốc).
- [x] `app_token` (đổi qua `POST /auth/token/exchange`) audience-bound (`aud` = ServiceDID) + `nonce` (nếu caller truyền) + sống-ngắn (15 phút mặc định) — verify được qua JWKS (Ed25519, `GET /.well-known/jwks.json`), xem `AppTokenVerifier` ở `src/verifier.ts`.
- [x] Issuer-side JWKS EdDSA — **đã xong** (xem trên; bản trước ghi đây là blocker của đội backend, nay đã lỗi thời — gỡ).
- [ ] **sender-constrained (DPoP) — CHƯA có.** `app_token` là **bearer thuần** ký EdDSA. Kiểm lại 2026-09-06 ở hàm đúc thẻ (`security/JwtServiceImpl.java`, `mintAppToken`): các claim được đặt là `iss`, `sub`, `aud`, `type`, `iat`, `exp`, và tuỳ chọn `nonce` / `key_id` / `key_role` — **không claim nào mang bằng chứng sở-hữu-khoá** (không `cnf`/`jkt`, không đòi chữ ký DPoP kèm mỗi lượt gọi). Dòng này từng bị đánh dấu "[x]" (ghi nhầm là đã có DPoP) — đã sửa cho khớp mã và giữ nguyên.
  **Hệ quả cho bên tích hợp, không phải chuyện lý thuyết:** ai cầm được chuỗi thẻ thì dùng được thẻ, nguyên vẹn tới `exp`, không cần chứng minh gì thêm. Nghĩa là thẻ phải sống ngắn (15 phút, đừng nới), **không được ghi vào log** (log ứng dụng, log truy cập proxy, sự kiện analytics, báo cáo lỗi), không đặt vào URL — và cất trong bộ nhớ tiến trình chứ đừng `localStorage`. Cần track riêng nếu §5.1 bắt buộc DPoP trước khi mở kênh 3 rộng rãi cho integrator ngoài.

**Frontend** — N/A cho silent (không có màn feature; UI do module feature tiêu thụ capability, thuộc đội SuperApp / đội backend).

**Verify (bằng chứng thật)**
- [x] Mobile: `flutter analyze + test` xanh (ví 44/44, pool 41/41, staking 17, dApp 38, cargo 141-154 tuỳ nhánh) — PR Core #28-33.
- [x] On-chain: deploy 2 validator Preprod verify qua Blockfrost (tx `b22bc207…`).
- [ ] Backend `curl` endpoint thật — thuộc đội backend (PhoenixKey-Database).

**Registry & Governance** — [ ] chờ Registry permissionless + DAO hậu kiểm (§6).

---

## 7. Tham chiếu
- Chuẩn: `SuperApp/Specs/INTEGRATION-STANDARD.md` (v0.1).
- Spec PhoenixKey: `PhoenixKey-Specs/` (Whitepaper + 8 module Vi-Feat/Math/Tech).
- Code PR đợt 2026-07-14: Core #28-33, Validator #28-29, Database #56.

*Phoenix agent — 2026-07-14.*
