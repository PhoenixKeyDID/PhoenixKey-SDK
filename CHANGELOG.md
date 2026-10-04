# Changelog

Dạng đánh số: trước 1.0, thay đổi phá vỡ tương thích tăng số minor (tiền lệ: 0.6.1 → 0.7.0, #34).

## 0.8.0

### Gỡ (phá vỡ tương thích)

- Gỡ ba phương thức của `WakemeModule`: `quoteMagic()`, `checkoutMagic()`, `getMagicOrder()`.
- Gỡ bốn kiểu đi kèm khỏi `src/wakeme.ts` và khỏi export của gói: `WakemeMagicQuoteRequest`, `WakemeMagicQuote`, `WakemeMagicCheckout`, `WakemeMagicOrderStatus`.
- Gỡ `WalletModule.claimMagic()` (gọi `POST /wallet/magic/claim`) và kiểu `MagicClaimResult` (cả khỏi export của gói). Máy chủ luôn trả **410** mã `MAGIC_CLAIM_DEPRECATED` (1324) (`WalletController.magicVaultClaimGone`, PhoenixKey-Database `a3e2c2d`): MAGIC là tài khoản kế toán trong két, không đúc vào ví. Đọc số dư MAGIC qua `getBalance()` / `getVaultMagic()`.

**Vì sao.** Module GetMAGIC (mua CARP bằng tiền pháp định) đã bỏ khỏi hệ từ 2026-09-14. Cả ba đường mà ba hàm này gọi — `POST /wakeme/getmagic/quote`, `POST /wakeme/getmagic/checkout`, `GET /wakeme/getmagic/{orderId}` — nay luôn trả **410** với mã lỗi `GETMAGIC_MODULE_RETIRED` (1364) (`WakemeController`, PhoenixKey-Database). Hàm SDK nào gọi tới đó cũng hỏng ở phía người dùng; giữ chúng chỉ mời bên tích hợp dựng màn hình mua MAGIC cho một thứ không bao giờ quay lại.

**Nên dùng gì thay.** Không có thay thế; luồng MAGIC đi qua két MAGIC. Phần đọc MAGIC sinh từ số dư LAMP (`getVaultMagic()`, `getGenEntry()`) vẫn còn nguyên.

**Việc cần làm khi nâng cấp.** Xoá mọi chỗ gọi bốn hàm trên (`quoteMagic`, `checkoutMagic`, `getMagicOrder`, `claimMagic`) và mọi chỗ `import` năm kiểu trên. Bên còn ghim SDK ≤ 0.7.x sẽ nhận `PhoenixKeyError` mang `status: 410` từ máy chủ, không phải 404.
