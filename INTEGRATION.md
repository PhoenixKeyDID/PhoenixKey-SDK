# PhoenixKey — Platform Integration Manifest

> **Là gì**: Khai báo tích hợp của platform **PhoenixKey** — tuân thủ **MagicLamp Platform Integration Standard** (L1 Ecosystem Standard, `SuperApp/Specs/INTEGRATION-STANDARD.md`, v0.1). File này KHÔNG định nghĩa lại chuẩn; nó là bản CONFORMANCE của PhoenixKey theo chuẩn đó.
> **Kiểu tích hợp**: `silent` (§1.3) — PhoenixKey không chiếm UI; cung service API + capability cho module khác. KHÔNG khai `entrypoint`/`route`/`icon`/`navSlot`.
> **Vai trò đặc biệt**: PhoenixKey DID là **root danh tính toàn hệ** (§3.1) — mọi module tiêu thụ danh tính qua service API của PhoenixKey.
> **Owner**: Aladin (founder) · Phoenix agent giữ interface contract. **Cập nhật**: 2026-07-21.
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

Bảng cho integrator (SuperApp) biết **build được vào cái gì NGAY**. Đối chiếu ngày **2026-07-24** với `GET /api/v1/v3/api-docs` trên prod — **61 route đang phục vụ**.

Cột trạng thái:
- `READY` — gọi được, có nghiệp vụ thật đằng sau.
- `KHUNG` — route đã công bố nhưng trả mã **9501 "Endpoint not yet implemented"**; đang chờ phụ thuộc ngoài. Client nối trước được, chỉ cần xử mã 9501 như "chưa bật".
- `CHỜ MERGE` — mã đã viết, PR mở, chưa lên prod.
- `MISSING` — chưa có route.

| Năng lực | Endpoint (prefix `/api/v1`) | Trạng thái |
|---|---|---|
| **Tạo DID** | `POST /identity/register` (Person) · `POST /identity/org/create` · `/identity/org/founding` · `POST /identity/asset/create` · resolve `GET /identity/{did}/document` · `/identifiers/{did}` (W3C) · `/identity/{did}/pubkey` · `/identity/{did}/status` | **READY** |
| **Chữ ký phiên web** (QR-pairing) | `POST /auth/session/init` → `GET /auth/session/{id}/stream` (SSE) → mobile `POST /auth/session/{id}/approve` → web nhận `sessionToken` (JWT 1h) + `linkedDeviceToken` (30d); SSO `POST /auth/token/exchange` | **READY** |
| **Nhận ADA / xem số dư** | `POST /wallet/register` (Phoenix custody) · `POST /wallet/standard/register` (CIP-1852) · `GET /wallet/{did}/all` · `GET /wallet/standard/{did}` (số dư ADA/LAMP/CARP từ Blockfrost). **Số lượng on-chain trả về là JSON _string_** (oildrop/lovelace/nanoMAGIC) — xem §"Hợp đồng số lớn" | **READY** (string-serialize: **CHỜ MERGE** Database PR #102) |
| **GetLAMP v5** (khoá 1001 LAMP vào vault) | `POST /activation/getlamp/build` (dựng tx chưa ký vào-vault + khoá `conditional_lamp`) → client Enclave ký → `POST /activation/getlamp/submit` | **KHUNG** — chờ deploy validator `activation_vault` |
| Vault Wakeme — đọc | `GET /activation/vault/{did}` (bảng điều khiển 2 pha) · `GET /activation/pot` (sức khoẻ pot + D hiện tại) | **KHUNG** — chờ deploy validator + Registry |
| Activation cũ (luồng Genie) | `POST /activation/initiate` → `/activation/{id}/confirm-payment` → `/activation/{id}/submit-tx` · SSE `/activation/{id}/events` · `/status` · `/cancel` | **READY** — nhưng là mô hình cũ, GetLAMP v5 thay thế |
| Guardian recovery | `POST /guardians/add` · `/guardians/remove` (owner-signed) | **READY** |
| Khoá on-chain | `POST /keys/authorize` · `/keys/revoke` · `/keys/rotate` (trả txHash) | **READY** |
| Device recovery (Mode B) | `POST /identity/recover-device` (gắn HW key máy mới bằng TAAD_Key) | **READY** |
| Seed export | `POST /seed/export-request` (rotate-before-reveal) | **READY** |
| Sign-relay (web tạo intent, mobile ký) | `POST /sign/request` → `GET /sign/request/{id}` → `POST /sign/{id}/approve` (verify ECDSA + SSE trả sig) | **READY** |
| Config/health | `GET /health/cardano` (network, `lamp_policy_id`, hash+địa chỉ TAAD) · `GET /actuator/health` · `GET /.well-known/jwks.json` | **READY** (xem cảnh báo cấu hình bên dưới) |
| **Sinh MAGIC từ số dư LAMP** | `GET /activation/vault/{did}/magic` (MAGIC hằng ngày — **đọc số dư**, không đụng LAMP) · `GET /activation/gen-entry` (ranh giới engine Gen ↔ SDK MAGIC). Trường `magic` trong `GET /wallet/{did}/all` hiện trả 0 | **KHUNG** — chờ engine Gen bên MAGIC. Hai đường chính thống: **InstantGen** (tiêu ngay) + **ScheduleGen** (các epoch sau). Không có đường thứ ba |
| **Gửi ADA** (build/submit tx tổng quát) | `POST /wallet/tx/submit` — client dựng+ký CBOR local, backend relay lên chain (không state). Khác `/activation/{id}/submit-tx` (gắn state machine activation) | **CHỜ MERGE** (Database PR #76) |
| **OrgDID uỷ-quyền thao tác LAMP** | `POST /identity/org/{orgDid}/mint-lamp` — OrgDID single-owner ký challenge → server phát **Grant** uỷ-quyền (`action` = `mint:LAMP`/`pot:fund`/`pot:distribute`). **KHÔNG đúc LAMP, KHÔNG submit tx** — chỉ verify chữ ký controller + phát Grant tự-verify (Anchorme §11.2). Xem mẫu §"Grant uỷ-quyền LAMP" | **CHỜ MERGE** (Database PR #119) |
| **Đúc/nạp LAMP thật (bên tiêu Grant)** | **KHÔNG phải endpoint PhoenixKey.** LAMP là 1 policy cố-định-36-tỷ, đúc một lần bởi kho phân phối (`dist_treasury`, thuộc **MagicLamp/LAMP**) — không có "mint LAMP theo từng OrgDID". `dist_treasury` **tiêu Grant ở trên** để ráp+ký+submit tx thật; PhoenixKey chỉ cấp OrgDID + uỷ-quyền. Tx đã ký relay qua `POST /wallet/tx/submit` | **ngoài phạm vi PhoenixKey** (→ LAMP) |
| **Pool — đọc** | `GET /pools?page=` · `GET /pools/{pool_id}` (số + metadata) · `GET /delegation/status/{stake_address}` (account chưa kích hoạt trả state đầy đủ, không 404) | **CHỜ MERGE** (Database PR #77) |
| **Tạo pool / SPO — ký** | không có endpoint; mobile dựng + ký cert đăng ký pool (CIP-1852) rồi gửi qua `POST /wallet/tx/submit`. Backend không giữ khoá vận hành pool | **client-side** |
| Danh sách OrgDID | `GET /identity/org` **không tồn tại**. Chỉ có tạo (`/identity/org/create`, `/identity/org/founding`, `/identity/org/{orgDid}/upgrade-authority`) | **MISSING** — client tự giữ danh sách |
| **Claim LAMP theo ETD / Airdrop / SRCL** | không có route nào (`/airdrop-claim/...` trả 404). Cơ chế Merkle + tham số đợt phát thuộc **LAMP**, không phải PhoenixKey | **MISSING** — chờ chốt ranh giới với LAMP |
| Tên người dùng, thiết bị, nhật ký, hỗ trợ | `POST /identity/username` · `GET /identity/by-username/{username}` · `GET /identity/nodes` · `POST /devices/register` · `GET /activity-logs` · `POST /support/session/init` · `POST /tx/estimate` | **READY** (`/tx/estimate` trả phí cố định 200.000 lovelace, chưa ước lượng thật) |
| ⚠ Tàn dư mô hình cũ — **đừng nối vào** | `POST /wallet/magic/claim` luôn trả **410 Gone** (MAGIC không đúc, không claim). `POST /activation/getmagic/{quote,checkout}` + `GET /activation/getmagic/{orderId}` là mua **CARP** bằng tiền pháp định — tên "GetMAGIC" là nhầm lẫn còn sót | **đang dọn** |

### Mẫu OrgDID — `POST /identity/org/create` (single-owner)

Đường **`/identity/org/create`** (KHÔNG phải `/identity/org` trơn — bản đó trả 404). Owner ký challenge canonical bằng HW_Key đang active của `ownerDid`.

```
POST /api/v1/identity/org/create
Content-Type: application/json
{
  "ownerDid": "did:phoenix:<b32-13>:<hex-64>",   // PersonDID sở hữu, phải đã register
  "name": "Công ty TNHH ABC",                     // 1–100 ký tự, KHÔNG cần duy nhất
  "registrationNumber": "0312345678",             // tuỳ chọn (MST); "" nếu không có
  "ownerSignature": "<hex>",                       // ECDSA/Ed25519 ký challenge dưới
  "nonce": "<1–64 ký tự>"                          // dùng-1-lần theo (ownerDid,nonce)
}

challenge = "PHOENIXKEY_ORG_MINT:" + ownerDid + ":" + name + ":" + (registrationNumber||"") + ":" + nonce

200 → { "code":1000, "message":"Org minted",
        "result": { "orgDid":"did:phoenix:...", "ownerDid":"did:phoenix:...", "txHash":"<hex>" } }
400 code 9800 thiếu field · 403 chữ ký owner sai · 404 ownerDid chưa register · 409 nonce đã dùng
```

`txHash` hiện là tx publish metadata-6789 (chuyển sang TAAD-UTxO-mint khi validator OrgDID deploy). `m-of-n`: `POST /identity/org/founding`; nâng single→threshold: `POST /identity/org/{orgDid}/upgrade-authority`.

### Grant uỷ-quyền LAMP — `POST /identity/org/{orgDid}/mint-lamp`

Nghĩa: OrgDID (GreenSun) là **danh tính ký/uỷ quyền** cho thao tác LAMP treasury/pot — **KHÔNG đúc token**. Endpoint verify controller của OrgDID đã ký, rồi phát **Grant** tự-verify (Anchorme §11.2). `dist_treasury` (MagicLamp) tiêu Grant để ráp+ký+submit tx thật. LAMP giữ cung cố-định 36 tỷ.

```
POST /api/v1/identity/org/{orgDid}/mint-lamp
Content-Type: application/json
{
  "action": "mint:LAMP",              // mint:LAMP | pot:fund | pot:distribute
  "resource": "<pot-id / addr kho>",  // đích của action (≤200 ký tự), opaque với backend
  "amountLamp": "26000000000000000",  // oildrop (đơn-vị-nhỏ-nhất) — CHUỖI big-number
  "granteeDid": "did:phoenix:...",    // tuỳ chọn: bên được uỷ quyền thực thi (vd operator dist_treasury)
  "validUntilSlot": 200000000,        // tuỳ chọn nhưng NÊN đặt hạn (slot)
  "ownerDid": "did:phoenix:...",      // controller single-owner của orgDid (phải == owner của org)
  "ownerSignature": "<hex>",          // ký challenge dưới
  "nonce": "<1–64 ký tự>"             // dùng-1-lần theo (ownerDid,nonce)
}

challenge = "PHOENIXKEY_ORG_LAMP:" + orgDid + ":" + action + ":" + amountLamp + ":"
          + resource + ":" + (granteeDid||"") + ":" + (validUntilSlot||"") + ":" + nonce

200 → { "code":1000, "message":"LAMP authorization grant issued",
        "result": { "grantId":"<uuid>", "grantorDid":"<orgDid>", "granteeDid":..., "action":"mint:LAMP",
                    "resource":..., "amountLamp":"26000000000000000", "validFromSlot":..., "validUntilSlot":...,
                    "nonce":..., "status":"ISSUED", "signerDid":..., "signerPublicKeyHex":"<hex>",
                    "signature":"<hex>", "canonicalChallenge":"PHOENIXKEY_ORG_LAMP:...", "revocable":true } }
403 chữ ký sai / signer không phải controller · 404 orgDid không tồn tại · 409 nonce đã dùng · 409 org không single-owner (m-of-n chưa hỗ trợ) · 400 validUntilSlot đã quá hạn
```

`dist_treasury` xác minh Grant bằng cách re-verify `signature` trên `canonicalChallenge` với `signerPublicKeyHex` (controller HIỆN-TẠI của `grantorDid`) + còn hạn + chưa thu-hồi. `amountLamp` là CHUỖI oildrop — parse bằng `BigInt`.

### Hợp đồng số lớn — số lượng on-chain là JSON _string_

Tổng cung LAMP = 3,6×10¹⁶ oildrop > `Number.MAX_SAFE_INTEGER` (9,007×10¹⁵). Vì vậy các trường **số lượng đơn-vị-nhỏ-nhất** (`balances.{lovelace,lamp,carp}`, `magic.{available,accrued}`, `amountLamp/Lovelace`, `dOildrop`, `potBalanceLamp`) serialize thành **chuỗi**, không phải number — để `JSON.parse` không mất chữ số ở ví/kho lớn. Client parse bằng `BigInt`/`bigint`. Trường **slot/ngày/phase/đếm** vẫn là number. (Đổi này: Database PR #102, CHỜ MERGE — trước merge các trường trên còn là number.)

> **Prod ĐANG SỐNG.** Base URL `https://api.phoenixkey.me/api/v1` — mọi route nằm dưới context-path `/api/v1`; gốc `https://api.phoenixkey.me/` trả 404 là **đúng hành vi**, không phải sự cố. Điểm kiểm nhanh:
>
> ```
> GET https://api.phoenixkey.me/api/v1/actuator/health   → 200 {"status":"UP"}
> GET https://api.phoenixkey.me/api/v1/health/cardano    → 200
>      Swagger  https://api.phoenixkey.me/api/v1/swagger-ui.html
> ```
>
> **⚠ Cấu hình prod còn thiếu (ảnh hưởng client):** `/health/cardano` hiện trả `lamp_policy_id` rỗng và `taad_script_address` / `taad_script_cbor_hex` / `taad_script_hash_history` rỗng. Client đối chiếu **policy-id** để chống token giả (fail-closed) → thiếu `lamp_policy_id` thì LAMP thật cũng bị chặn; thiếu địa chỉ/CBOR TAAD thì không dựng được tx chạm TAAD. Đây là biến môi trường chưa nạp trên prod, không phải thiếu code. `magic_policy_id` rỗng là **đúng** — MAGIC là tài khoản trong vault, không có policy-id.

> **On-chain (tham chiếu):** 2-of-2 `controller_pkh ∧ device_pkh` đã canonical trong validator (`auth_logic.ak`, 463 test PASS) nhưng CHƯA re-apply vào deploy artifact — anchor/ví đang live là bản 1-of-1 cũ. `did_payment`/`did_stake`/`limit_meter_vault`/`activation_vault` compile+test xanh, phần lớn BUILT chưa deploy. Chỉ TAAD có UTxO thật trên Preview.

## 3. Identity & Data compliance (§3)

- **§3.1 DID root**: PhoenixKey DID = root danh tính; module khác KHÔNG redefine, chỉ tiêu thụ qua service API. Issuer-side EdDSA + `/.well-known/jwks.json` thuộc **Long** (Claude KHÔNG sửa PhoenixKey backend).
- **§3.2 INV-1**: store DID = single source of truth; mọi client (kể cả app native) ghi qua fabric API versioned + idempotency key. Client KHÔNG ghi data layer trực tiếp.
- **§3.4 INV-3**: on-chain (TAAD anchor) CHỈ chứa **hash/commitment/pointer** — KHÔNG PII/sinh trắc raw. PII + sinh trắc off-chain, store tại VN, erasable. Consent per-host. Capability cưỡng chế qua broker.
- **LoA (§3.1)**: chỉ DID sinh trắc gốc có quyền governance; DID liên kết host ngoài (LoA thấp) chỉ dùng tính năng.

## 4. Embed / kênh 3 (§5) — federation danh tính

- Bằng chứng danh tính sinh + ký TRONG app PhoenixKey gốc (Secure Enclave) hoặc QR challenge-response. **DID gốc/sinh trắc KHÔNG BAO GIỜ vào WebView host.**
- Host chỉ nhận token **audience-bound (host-id+module-id+device+nonce) + sender-constrained (DPoP), sống-ngắn**.
- **Blocker cho kênh 3**: issuer-side mint EdDSA + JWKS — thuộc Long. Consumer-side (ProofChat) đã verify.

## 5. Anchor on-chain đã deploy (bằng chứng — Preprod)

Deploy tx: `b22bc2077bd3e91d306faa6324d70083701b7d0ebda43e40e1a6943a9dc16c5b` (verify Blockfrost hash-at-index).
- `TAAD_ANCHOR_POLICY_ID` = `0f665f9967e5b735949e4def618b6b56cff9e18f0f74571303f49a3f`
- `lamp_policy` (validator) = `f1884536db71ba734e94d4aa451376d45fa49c24f03caaf1e5165408`
- **tLAMP token** (canonical cả Preview+Preprod, DÙNG cho hiển thị/chuyển LAMP) = `7a1a7aed5ec47acc37b6fa82695c1219bf76895b505b01161367adf9` — LƯU Ý KHÁC `lamp_policy`-validator (2 policy khác nhau).

Giao dịch minh hoạ khác: Wakeme 1001 tLAMP Preview `01139ba8af1f7556b70a82126aff7fd1b940bc8157c973b45e019e27c7870f16`.

## 6. Checklist tuân thủ (§8) — trạng thái PhoenixKey (silent)

**Manifest & Config**
- [x] Manifest silent hợp lệ; `capabilities` tối thiểu; `mergePolicy` khai rõ. `config.schema.json` declarative — chờ hoàn thiện.
- [ ] Static capability scan ở Registry — chờ Registry.

**Identity & Data**
- [x] Ghi data qua fabric API + idempotency (INV-1). On-chain chỉ hash/commitment (TAAD anchor) (INV-3). Consent per-host + broker default-deny.

**Embed (kênh 3)**
- [x] Token audience-bound + DPoP + nonce; credential/biometric KHÔNG vào WebView.
- [ ] Issuer-side JWKS EdDSA — **BLOCKER, thuộc Long**.

**Frontend** — N/A cho silent (không có màn feature; UI do module feature tiêu thụ capability, thuộc SuperApp/Long).

**Verify (bằng chứng thật)**
- [x] Mobile: `flutter analyze + test` xanh (ví 44/44, pool 41/41, staking 17, dApp 38, cargo 141-154 tuỳ nhánh) — PR Core #28-33.
- [x] On-chain: deploy 2 validator Preprod verify qua Blockfrost (tx `b22bc207…`).
- [ ] Backend `curl` endpoint thật — thuộc Long (PhoenixKey-Database).

**Registry & Governance** — [ ] chờ Registry permissionless + DAO hậu kiểm (§6).

---

## 7. Tham chiếu
- Chuẩn: `SuperApp/Specs/INTEGRATION-STANDARD.md` (v0.1).
- Spec PhoenixKey: `PhoenixKey-Specs/` (Whitepaper + 8 module Vi-Feat/Math/Tech).
- Code PR đợt 2026-07-14: Core #28-33, Validator #28-29, Database #56.

*Phoenix agent — 2026-07-14.*
