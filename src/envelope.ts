/**
 * PHOENIXKEY_RP_AUTH — khuôn thông điệp ký cho luồng đăng nhập bên tin cậy.
 *
 * Đặc tả đầy đủ + vector kiểm thử: `RP-AUTH-ENVELOPE.md`.
 *
 * Vì sao có tệp này: khuôn cũ nối chuỗi bằng dấu hai chấm
 * (`challenge:domain:timestamp`) nên KHÔNG đơn ánh — hai bộ trường khác nhau
 * dựng ra cùng một chuỗi byte, và khi đó một chữ ký lấy được ở bên tin cậy này
 * dùng lại được ở bên kia. Xem `RP-AUTH-ENVELOPE.md` §"Khuôn cũ hỏng thế nào".
 */

/** Tiền tố miền. Byte 0x00 cuối để không tiền tố nào là tiền tố của bản khác. */
export const RP_AUTH_PREFIX_V1 = "PHOENIXKEY_RP_AUTH:v1\u0000";

export type RpAuthFields = {
  user_did: string;
  domain: string;
  challenge: string;
  /** Giây từ epoch. Mã hoá u64 big-endian — không tràn sau 2038. */
  timestamp: number;
};

const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

/** Đóng khung độ dài: u32 big-endian độ dài byte, rồi chính các byte đó. */
function lengthPrefixed(s: string): Uint8Array {
  const body = utf8(s);
  const out = new Uint8Array(4 + body.length);
  new DataView(out.buffer).setUint32(0, body.length, false);
  out.set(body, 4);
  return out;
}

function u64be(v: number): Uint8Array {
  if (!Number.isInteger(v) || v < 0) {
    throw new RangeError(`timestamp phải là số nguyên không âm, nhận: ${v}`);
  }
  if (!Number.isSafeInteger(v)) {
    throw new RangeError(`timestamp vượt ngưỡng số nguyên an toàn: ${v}`);
  }
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(v), false);
  return out;
}

function concat(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/**
 * Dựng chuỗi byte được ký theo khuôn v1.
 *
 * Thứ tự trường là một phần của khuôn — đổi thứ tự là đổi khuôn.
 */
export function encodeRpAuthV1(f: RpAuthFields): Uint8Array {
  return concat([
    utf8(RP_AUTH_PREFIX_V1),
    lengthPrefixed(f.user_did),
    lengthPrefixed(f.domain),
    lengthPrefixed(f.challenge),
    u64be(f.timestamp),
  ]);
}

/**
 * Khuôn CŨ, giữ lại để nhận cả hai bản trong giai đoạn chuyển tiếp.
 *
 * @deprecated Sẽ bỏ khi mọi bên tin cậy đã chuyển. KHÔNG dùng cho tích hợp mới.
 */
export function encodeLegacyConcat(f: Pick<RpAuthFields, "domain" | "challenge" | "timestamp">): Uint8Array {
  return utf8(`${f.challenge}:${f.domain}:${f.timestamp}`);
}
