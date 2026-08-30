# PHOENIXKEY_RP_AUTH — khuôn thông điệp ký cho bên tin cậy

Tài liệu này định nghĩa **chuỗi byte được ký** trong luồng đăng nhập PhoenixKey.
Nó là hợp đồng giữa app (ký) và bên tin cậy (kiểm) — hai bên phải dựng ra cùng
một chuỗi byte, từng byte một, nếu không mọi chữ ký đều trượt.

Trước bản này, khuôn chỉ tồn tại trong mã của PhoenixKey chứ không tồn tại trong
bất cứ tài liệu nào bên tích hợp đọc được. Đó là lý do có ít nhất một bên đang ký
một khuôn khác hẳn.

## Khuôn cũ hỏng thế nào

Khuôn đang chạy nối chuỗi bằng dấu hai chấm:

```
challenge + ":" + domain + ":" + timestamp
```

Nó **không đơn ánh**. Hai bộ trường khác nhau dựng ra cùng một chuỗi byte:

```
{ challenge: "a",   domain: "b:c" }  →  "a:b:c:1755093600"
{ challenge: "a:b", domain: "c"   }  →  "a:b:c:1755093600"

sha256 cả hai = 5b6aab8240288e7c76f2c8d642d194b48e0a8482e9482e904c993bde576b9c23
```

Hệ quả không phải chuyện lý thuyết. Trường `domain` có mặt để **ràng chữ ký vào
đúng một bên tin cậy**, chặn dùng lại chữ ký sang bên khác. Vì khuôn nhập nhằng
nên một bên tin cậy chọn được `challenge` sao cho chuỗi byte cuối trùng với chuỗi
của một bên khác — và chữ ký lấy được ở mình dùng lại được ở bên kia. Đúng thứ
`domain` sinh ra để chặn thì nó không chặn.

Bài kiểm cố định lỗi này ở `test/envelope.test.ts`.

## Khuôn v1

```
message_bytes =
      "PHOENIXKEY_RP_AUTH:v1" ‖ 0x00
    ‖ LP(user_did)
    ‖ LP(domain)
    ‖ LP(challenge)
    ‖ U64BE(timestamp)

LP(s)     = U32BE(byte_length(utf8(s))) ‖ utf8(s)
U32BE(n)  = 4 byte, big-endian
U64BE(n)  = 8 byte, big-endian
```

Chữ ký: **ECDSA P-256 (prime256v1) trên `SHA-256(message_bytes)`** — không đổi so
với hiện tại, chỉ đổi thứ được băm.

### Vì sao từng chi tiết

| Chi tiết | Lý do |
|---|---|
| Tiền tố miền | Một chữ ký của luồng này không bao giờ dùng lại được cho luồng khác của PhoenixKey. Mỗi luồng một tiền tố riêng. |
| Byte `0x00` khép tiền tố | Không có bản nào là tiền tố của bản khác. Thiếu nó thì `:v1` là tiền tố của `:v10`, và hai khuôn lại nhập nhằng — đúng lỗi đang chữa. |
| Đóng khung độ dài | Ranh giới trường trở nên tường minh. Không còn ký tự nào cần thoát, không còn ký tự nào mang nghĩa cấu trúc. Đây là thứ đóng lỗ ở trên. |
| `U32BE` chứ không phải varint | Ai cũng hiện thực hoá đúng trong mọi ngôn ngữ mà không cần thư viện. Varint tiết kiệm vài byte và đổi lấy nhiều cách sai. |
| Có `user_did` trong thông điệp | Chữ ký ràng vào danh tính. Không lấy được chữ ký của người này dùng cho DID người kia. |
| `timestamp` là `U64BE` | Không tràn năm 2038. `U32` là một lỗi hẹn giờ. |
| Thứ tự trường cố định | Thứ tự **là một phần của khuôn**. Đổi thứ tự = đổi khuôn = phải tăng số bản. |

## Vector kiểm thử

So **từng byte** với `message_bytes`, đừng chỉ so hash cuối. Hash khớp thì mọi
thứ khớp, nhưng hash lệch thì nó không cho biết lệch ở đâu; chuỗi byte thì có.

| # | user_did | domain | challenge | timestamp |
|---|---|---|---|---|
| V1 | `did:phoenix:k7m2n4p9q3r5t` | `orilife.vn` | `a3f1c8e2` | 1755093600 |
| V2 | `did:phoenix:k7m2n4p9q3r5t` | *(rỗng)* | *(rỗng)* | 0 |
| V3 | `did:phoenix:k7m2n4p9q3r5t` | `b:c` | `a` | 1755093600 |
| V4 | `did:phoenix:k7m2n4p9q3r5t` | `c` | `a:b` | 1755093600 |
| V5 | `did:phoenix:k7m2n4p9q3r5t` | `ví.phượng-hoàng.vn` | `thử-thách-Ω` | 1755093600 |
| V6 | `did:phoenix:k7m2n4p9q3r5t` | `aladin.work` | `ff` | 4294967296 |

### V1 — trường hợp thường

```
message_bytes (85 byte)
50484f454e49584b45595f52505f415554483a763100000000196469643a7068
6f656e69783a6b376d326e34703971337235740000000a6f72696c6966652e76
6e00000008613366316338653200000000689c9a60

sha256 = aabb36245ff7985a2c52bbee3741fabf9d7e0474973912872eaba7aad10fda90
```

### V2 — trường rỗng

Trường rỗng phải hợp lệ về mã hoá: `LP("")` = bốn byte không, không byte nào nữa.

```
message_bytes (67 byte)
50484f454e49584b45595f52505f415554483a763100000000196469643a7068
6f656e69783a6b376d326e347039713372357400000000000000000000000000
000000

sha256 = 4d6ceefc5c3512c8c9b9e88624fb7f037c94312194cadecb2d78f98c06a2221c
```

### V3 — dấu hai chấm trong `domain`

```
message_bytes (71 byte)
50484f454e49584b45595f52505f415554483a763100000000196469643a7068
6f656e69783a6b376d326e347039713372357400000003623a63000000016100
000000689c9a60

sha256 = 2a0846223da83f242bfbd6282e6b86727def6691de5e7772edbad309e63dfa7b
```

### V4 — cặp va với V3 dưới khuôn cũ

V3 và V4 dựng ra **cùng một chuỗi byte** dưới khuôn cũ. Dưới v1 chúng khác nhau.
Đây là vector quan trọng nhất trong bộ — hiện thực hoá nào cho V3 và V4 ra cùng
kết quả là hiện thực hoá sai.

```
message_bytes (71 byte)
50484f454e49584b45595f52505f415554483a763100000000196469643a7068
6f656e69783a6b376d326e3470397133723574000000016300000003613a6200
000000689c9a60

sha256 = b8ada3e6e014150ed5919ad4facefb2fe48afffe73187d0bd709207da1cc2453
```

### V5 — phi-ASCII

Độ dài đếm bằng **byte UTF-8**, không phải ký tự, không phải đơn vị mã UTF-16.
Vector này bắt lỗi ở mọi ngôn ngữ đo chuỗi bằng ký tự (`ví` = 3 byte, `Ω` = 2
byte).

```
message_bytes (105 byte)
50484f454e49584b45595f52505f415554483a763100000000196469643a7068
6f656e69783a6b376d326e34703971337235740000001776c3ad2e7068c6b0e1
bba36e672d686fc3a06e672e766e0000000f7468e1bbad2d7468c3a163682dce
a900000000689c9a60

sha256 = 946013cd592935ba0e0c5c1a379450545663aec1d3875483aec19e8d4b25555b
```

### V6 — mốc thời gian vượt 32 bit

```
message_bytes (80 byte)
50484f454e49584b45595f52505f415554483a763100000000196469643a7068
6f656e69783a6b376d326e34703971337235740000000b616c6164696e2e776f
726b0000000266660000000100000000

sha256 = 0b9d639a74990928405af2fc433df40880582db83ca3ede0b4855f8574b808f1
```

## Chuyển tiếp

Đổi khuôn là đổi hợp đồng hai phía. App ký, máy chủ kiểm — đổi một bên trước là
mọi phiên đăng nhập gãy tức thì. Nên chuyển theo ba nhịp, và **đừng bên nào tự
đi trước**:

1. **Bên kiểm nhận cả hai khuôn.** SDK làm sẵn: thử v1, trượt thì thử khuôn cũ.
   `VerifyResult.envelope` trả về `"v1"` hoặc `"legacy"` — ghi lại giá trị đó thì
   đo được còn bao nhiêu phần trăm lưu lượng chưa chuyển, thay vì đoán.
2. **Bên ký chuyển sang v1.** App PhoenixKey và mọi bên tự dựng chữ ký.
3. **Tắt khuôn cũ** khi số đo ở nhịp 1 về không: `acceptLegacyEnvelope: false`.

```ts
const verifier = new PhoenixKeyVerifier({
  acceptLegacyEnvelope: true,   // nhịp 1-2
});

const r = await verifier.verifyAuthProof({ user_did, signature, challenge, domain, timestamp });
if (r.valid && r.envelope === "legacy") {
  metrics.increment("phoenixkey.auth.legacy_envelope");   // đo, đừng đoán
}
```

Trong lúc còn nhận khuôn cũ thì lỗ dùng-lại-chữ-ký ở trên **vẫn còn**. Đây là
đánh đổi có ý thức để không giết đường đăng nhập lần nữa, không phải chuyện đã
xong. Nhịp 3 mới là lúc lỗ đóng.

## Hai việc kèm theo, không thuộc khuôn nhưng thuộc cùng luồng

**Màn hình sinh trắc phải hiện tên bên nhận.** Bấm vân tay mà không biết đang ký
cho ai là lỗi thiết kế, và không khuôn nào chữa được: khuôn ràng chữ ký vào
`domain`, nhưng nếu người dùng không thấy `domain` thì họ vẫn ký cho bất cứ ai
hỏi. Việc này ở app, không ở đây.

**Đệm khoá công khai đang hở.** `verifier.ts` đệm khoá 5 phút và không có đường
vô hiệu hoá, nên sau khi nạn nhân xoay khoá thì khoá cũ còn kiểm được tới 5 phút.
Chi tiết và hướng sửa ở issue #11. Trong lúc chờ, luồng nào cần chắc thì đặt
`cacheTtlMs: 0`.

Phoenix agent
