import { createHash } from "node:crypto";
import { encodeRpAuthV1, encodeLegacyConcat, RP_AUTH_PREFIX_V1 } from "../src/envelope";

const hex = (u: Uint8Array) => Buffer.from(u).toString("hex");
const sha = (u: Uint8Array) => createHash("sha256").update(Buffer.from(u)).digest("hex");

const DID = "did:phoenix:k7m2n4p9q3r5t";

/**
 * Vector cố định. Đây là HỢP ĐỒNG với bên tin cậy — sửa một giá trị ở đây là
 * làm gãy mọi bên đã hiện thực hoá theo. Muốn đổi khuôn thì tăng số bản (v2),
 * đừng sửa vector của v1.
 */
const VECTORS = [
  {
    id: "V1",
    name: "trường hợp thường",
    fields: { user_did: DID, domain: "orilife.vn", challenge: "a3f1c8e2", timestamp: 1755093600 },
    len: 85,
    sha256: "aabb36245ff7985a2c52bbee3741fabf9d7e0474973912872eaba7aad10fda90",
  },
  {
    id: "V2",
    name: "trường rỗng",
    fields: { user_did: DID, domain: "", challenge: "", timestamp: 0 },
    len: 67,
    sha256: "4d6ceefc5c3512c8c9b9e88624fb7f037c94312194cadecb2d78f98c06a2221c",
  },
  {
    id: "V3",
    name: "dấu hai chấm trong domain",
    fields: { user_did: DID, domain: "b:c", challenge: "a", timestamp: 1755093600 },
    len: 71,
    sha256: "2a0846223da83f242bfbd6282e6b86727def6691de5e7772edbad309e63dfa7b",
  },
  {
    id: "V4",
    name: "cặp va với V3 dưới khuôn cũ",
    fields: { user_did: DID, domain: "c", challenge: "a:b", timestamp: 1755093600 },
    len: 71,
    sha256: "b8ada3e6e014150ed5919ad4facefb2fe48afffe73187d0bd709207da1cc2453",
  },
  {
    id: "V5",
    name: "phi-ASCII, UTF-8 nhiều byte",
    fields: { user_did: DID, domain: "ví.phượng-hoàng.vn", challenge: "thử-thách-Ω", timestamp: 1755093600 },
    len: 105,
    sha256: "946013cd592935ba0e0c5c1a379450545663aec1d3875483aec19e8d4b25555b",
  },
  {
    id: "V6",
    name: "mốc thời gian vượt 32 bit",
    fields: { user_did: DID, domain: "aladin.work", challenge: "ff", timestamp: 4294967296 },
    len: 80,
    sha256: "0b9d639a74990928405af2fc433df40880582db83ca3ede0b4855f8574b808f1",
  },
] as const;

describe("khuôn PHOENIXKEY_RP_AUTH v1", () => {
  it("tiền tố khép bằng byte 0x00", () => {
    expect(RP_AUTH_PREFIX_V1).toBe("PHOENIXKEY_RP_AUTH:v1\u0000");
    expect(RP_AUTH_PREFIX_V1.charCodeAt(RP_AUTH_PREFIX_V1.length - 1)).toBe(0);
  });

  it.each(VECTORS)("$id — $name khớp vector", (v) => {
    const msg = encodeRpAuthV1(v.fields);
    expect(msg.length).toBe(v.len);
    expect(sha(msg)).toBe(v.sha256);
  });

  it("mở đầu bằng đúng tiền tố", () => {
    const msg = encodeRpAuthV1(VECTORS[0].fields);
    expect(hex(msg).startsWith(Buffer.from(RP_AUTH_PREFIX_V1, "utf8").toString("hex"))).toBe(true);
  });

  it("đóng khung độ dài u32 big-endian", () => {
    const msg = encodeRpAuthV1({ user_did: "ab", domain: "", challenge: "", timestamp: 0 });
    const at = Buffer.from(RP_AUTH_PREFIX_V1, "utf8").length;
    expect(Array.from(msg.slice(at, at + 4))).toEqual([0, 0, 0, 2]);
  });
});

describe("khuôn v1 đơn ánh — chỗ khuôn cũ hỏng", () => {
  it("khuôn CŨ dựng CÙNG chuỗi byte cho hai bộ trường khác nhau", () => {
    const a = encodeLegacyConcat(VECTORS[2].fields);
    const b = encodeLegacyConcat(VECTORS[3].fields);
    expect(Buffer.from(a).toString("utf8")).toBe("a:b:c:1755093600");
    expect(Buffer.from(b).toString("utf8")).toBe("a:b:c:1755093600");
    expect(sha(a)).toBe(sha(b));
  });

  it("khuôn MỚI tách hai bộ đó ra", () => {
    const a = encodeRpAuthV1(VECTORS[2].fields);
    const b = encodeRpAuthV1(VECTORS[3].fields);
    expect(sha(a)).not.toBe(sha(b));
  });

  it("dịch một ký tự giữa hai trường liền kề luôn đổi chuỗi byte", () => {
    const seen = new Set<string>();
    for (let cut = 0; cut <= 6; cut++) {
      const whole = "abcdef";
      const msg = encodeRpAuthV1({
        user_did: DID,
        domain: whole.slice(0, cut),
        challenge: whole.slice(cut),
        timestamp: 1755093600,
      });
      seen.add(sha(msg));
    }
    expect(seen.size).toBe(7);
  });
});

describe("mốc thời gian", () => {
  it("từ chối số âm", () => {
    expect(() => encodeRpAuthV1({ user_did: DID, domain: "d", challenge: "c", timestamp: -1 })).toThrow(RangeError);
  });

  it("từ chối số thực", () => {
    expect(() => encodeRpAuthV1({ user_did: DID, domain: "d", challenge: "c", timestamp: 1.5 })).toThrow(RangeError);
  });

  it("từ chối số vượt ngưỡng an toàn", () => {
    expect(() =>
      encodeRpAuthV1({ user_did: DID, domain: "d", challenge: "c", timestamp: Number.MAX_SAFE_INTEGER + 2 }),
    ).toThrow(RangeError);
  });
});
