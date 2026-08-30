# Review PR — SDK `feat/testnet-release-claude-drop`

Chào anh, PR gọn (4 file, 259 dòng) — code chất lượng tốt, theo đúng convention của các module
cũ (fetcher + SSE + token getter pattern). `bun run typecheck` pass sạch. Em không có blocker,
chỉ note 1 bug + vài cleanup.

---

## 🟠 Bug — `mockConfirmPayment` sẽ luôn fail với BE

```ts
// activation.ts:131-133
body: JSON.stringify({
  payment_reference: `MOCK-${activationId.substring(0, 8)}`,
})
```

BE `ActivationServiceImpl.confirmPayment` validate:
```java
if (paymentReference != null && !paymentReference.equals(activation.getPaymentReference()))
    throw new AppException(ErrorCode.ACTIVATION_INVALID_STATE, "Payment reference mismatch");
```

BE generate `paymentReference` format `PK<8hex>+<6hex>` (xem `generatePaymentReference`) — client
không có cách nào biết giá trị thật vì `ActivationStatusResponse` không expose field này. Mock
`MOCK-...` luôn mismatch → throw error. **FE GetLampPanel cũng dính lỗi y hệt** (cùng pattern).

**Fix** (1 trong 3):
- SDK gửi body `{}` rỗng (BE skip validation khi null) — đơn giản nhất, em recommend
- BE skip `payment_reference` check khi có valid `X-Admin-Token` (testnet bypass)
- BE expose `payment_reference` qua `getStatus` response

---

## 🟡 Thiếu method `submitTx` cho Genie

BE có `POST /activation/{id}/submit-tx` (Genie ký Cardano CBOR, submit qua server). SDK chưa
expose method tương ứng. Nếu Genie app dùng SDK → cần thêm `activation.submitTx(activationId,
signedTxCbor)`.

---

## 🟡 Minor cleanup

- **`extrapolateAccrued` cần `slotOrigin` magic number** — caller phải tự biết Cardano slot 0 epoch ms (preprod khác mainnet). Đề xuất export constants:
  ```ts
  export const PREPROD_SLOT_ORIGIN_MS = 1666656000000;
  export const MAINNET_SLOT_ORIGIN_MS = 1596059091000;
  ```
  Hoặc bundle vào `NetworkModule`.
- **`Balance.balance_lovelace: number`** — ADA max supply ~4.5e16 lovelace, gần `Number.MAX_SAFE_INTEGER` (9e15). Recommend `bigint` cho fields lovelace + lamp.
- **Convenience**: `wallet.getMyBalance()` đọc `userDid` từ session token — tránh caller pass lại.
- **Version bump**: `package.json` còn `0.2.0` — adding 2 modules là minor bump → **`0.3.0`**.
- **README + CHANGELOG**: thêm 2 module mới.
- **Tests**: chưa có test file cho 2 module mới. Em chỉ note — wallet/activation flow phức tạp hơn các module read-only cũ.

---

## ✅ Em thấy ổn

- API surface clean, theo đúng pattern của các module cũ.
- Type definitions khớp BE schema (snake_case, đúng status enum, `magic_rate_per_slot: string`
  để tránh float precision).
- Token getter pattern `_getSessionToken: () => string | null` consistent.
- `openEventStream` reuse `ResilientSSE` chuẩn — không reinvent.
- Comment + JSDoc rõ ràng, có spec reference.
- FE alignment fix `tx_hash` (commit `7542e46`) đã đúng — match với BE Jackson snake_case.

---

Em xong review. Anh xem có gì chưa ổn không ạ.
