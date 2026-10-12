# Changelog

Dạng đánh số: trước 1.0, thay đổi phá vỡ tương thích tăng số minor (tiền lệ: 0.6.1 → 0.7.0, #34).

## 0.9.1

### Thêm

- Added: `WakemeModule.repinBuild` / `repinSubmit` (`POST /wakeme/repin/build`, `/wakeme/repin/submit`). Repin only works on v5b vaults; on v6 the service returns 9501. Kiểu mới: `RepinBuildRequest`, `RepinBuildResponse`; `repinSubmit` dùng lại `WakemeSubmitResponse`.

### Sửa

- `FeesModule.estimate()`, `NetworkModule.getNodes()` và `SupportModule.initSession()` nay gửi `Authorization: Bearer <session_token>`. Trước đây ba hàm gọi `GET /tx/estimate`, `GET /identity/nodes` và `POST /support/session/init` không kèm token, trong khi cả ba route đều nằm ngoài các danh sách công khai của `AuthRequiredInterceptor` (PhoenixKey-Database) ⟹ mọi lần gọi nhận **401** (mã 1304, "Missing Bearer token"; đo trên Preprod 2026-10-12 cho hai route đầu). Không có token thì mỗi hàm ném `Error("Not authenticated")`, không đi mạng.
- Docstring của `FeesModule.estimate()` từng ghi "Public — không cần auth"; đã sửa.
- Constructor của ba module nhận thêm tham số thứ hai `getSessionToken: () => string | null`, giống `WalletModule`. Dùng qua `PhoenixKeyClient` thì không phải làm gì: `client.fees`, `client.network`, `client.support` đã được nối sẵn với phiên. Chỉ ai tự `new FeesModule(baseUrl)` / `new NetworkModule(baseUrl)` / `new SupportModule(baseUrl)` mới phải truyền thêm getter.

## 0.9.0

### Sửa

- `WalletModule.getBalance()` nay gửi `Authorization: Bearer <session_token>`. Trước đây hàm gọi `GET /wallet/{did}/balance` không kèm token, trong khi máy chủ ép Bearer và chỉ cho đọc ví của chính DID trong phiên (`WalletController.balance` → `requireSelfDid`, PhoenixKey-Database `5a587312`) ⟹ mọi lần gọi đều nhận **401**. Không có token thì hàm ném `Error("Not authenticated")`, không đi mạng. `resolveOwnerPkh()` đi qua `getBalance()` nên cũng cần phiên của chính DID đó.
- `getBalance()` được đánh dấu `@deprecated`: route máy chủ là `@Deprecated(forRemoval = true)` và năm trường MAGIC của nó luôn là `0`/`""`.

### Thêm

- `WalletModule.getAll(did)` gọi `GET /wallet/{did}/all` (Bearer, chính chủ): cả ví Phoenix lẫn Standard, khối `magic` và khối LAMP trong két Wakeme trong một lần gọi. Xuất thêm các kiểu `WalletsAll`, `WalletEntry`, `WalletAddresses`, `WalletBalances`, `MagicAccount`, `MagicAbsentReason`, `VaultLamp`, `VaultAbsentReason`.

### Phá vỡ tương thích (mức kiểu)

- Kiểu `Balance`: `balance_lovelace`, `balance_lamp`, `balance_magic`, `magic_accrued` đổi từ `number` sang `string`, thêm `balance_carp: string`. Đây là hình thật trên dây: máy chủ serialize các số này thành chuỗi thập phân (`WalletDtos.BalanceResponse`, `ToStringSerializer`) vì LAMP tính bằng oildrop vượt `Number.MAX_SAFE_INTEGER`. Kiểu cũ khai sai; lúc chạy, các trường này vốn đã là chuỗi.

**Việc cần làm khi nâng cấp.** Chỗ nào làm toán trên các trường trên thì đổi sang `BigInt(value)`. Chỗ nào gọi `getBalance()` thì cấp `getSessionToken` cho client, hoặc chuyển sang `getAll()`.

## 0.8.0

### Gỡ (phá vỡ tương thích)

- Gỡ ba phương thức của `WakemeModule`: `quoteMagic()`, `checkoutMagic()`, `getMagicOrder()`.
- Gỡ bốn kiểu đi kèm khỏi `src/wakeme.ts` và khỏi export của gói: `WakemeMagicQuoteRequest`, `WakemeMagicQuote`, `WakemeMagicCheckout`, `WakemeMagicOrderStatus`.
- Gỡ `WalletModule.claimMagic()` (gọi `POST /wallet/magic/claim`) và kiểu `MagicClaimResult` (cả khỏi export của gói). Máy chủ luôn trả **410** mã `MAGIC_CLAIM_DEPRECATED` (1324) (`WalletController.magicVaultClaimGone`, PhoenixKey-Database `a3e2c2d`): MAGIC là tài khoản kế toán trong két, không đúc vào ví. Đọc số dư MAGIC qua `getBalance()` / `getVaultMagic()`.

**Vì sao.** Module GetMAGIC (mua CARP bằng tiền pháp định) đã bỏ khỏi hệ từ 2026-09-14. Cả ba đường mà ba hàm này gọi — `POST /wakeme/getmagic/quote`, `POST /wakeme/getmagic/checkout`, `GET /wakeme/getmagic/{orderId}` — nay luôn trả **410** với mã lỗi `GETMAGIC_MODULE_RETIRED` (1364) (`WakemeController`, PhoenixKey-Database). Hàm SDK nào gọi tới đó cũng hỏng ở phía người dùng; giữ chúng chỉ mời bên tích hợp dựng màn hình mua MAGIC cho một thứ không bao giờ quay lại.

**Nên dùng gì thay.** Không có thay thế; luồng MAGIC đi qua két MAGIC. Phần đọc MAGIC sinh từ số dư LAMP (`getVaultMagic()`, `getGenEntry()`) vẫn còn nguyên.

**Việc cần làm khi nâng cấp.** Xoá mọi chỗ gọi bốn hàm trên (`quoteMagic`, `checkoutMagic`, `getMagicOrder`, `claimMagic`) và mọi chỗ `import` năm kiểu trên. Bên còn ghim SDK ≤ 0.7.x sẽ nhận `PhoenixKeyError` mang `status: 410` từ máy chủ, không phải 404.
