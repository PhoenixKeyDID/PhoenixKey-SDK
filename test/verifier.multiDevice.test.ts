import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";
import { PhoenixKeyVerifier } from "../src/verifier";
import type { SignIntent } from "../src/types";

const BASE = "https://api.example.test";
const DID = "did:phoenix:aaaaaaaaaaaaa:" + "0".repeat(64);

afterEach(() => {
  jest.restoreAllMocks();
});

const hex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

type Rec = { public_key_hex: string; key_role: string; status: string; revoked_at?: string | null };

/** Một thiết bị = một khoá P-256 thật. */
function device() {
  const priv = p256.utils.randomPrivateKey();
  return { priv, pubHex: hex(p256.getPublicKey(priv)) };
}

function intent(): SignIntent {
  return {
    type: "TRANSFER",
    body: { amount: "1" },
    domain: "example.test",
    nonce: "ab".repeat(16),
    timestamp: Math.floor(Date.now() / 1000),
    display_text: "test",
  };
}

/** Chuỗi byte được ký đúng như verifier dựng: JSON chuẩn tắc, khoá sắp xếp. */
function canonical(o: unknown): string {
  if (o === null || o === undefined) return "null";
  if (typeof o !== "object") return JSON.stringify(o);
  if (Array.isArray(o)) return `[${o.map(canonical).join(",")}]`;
  const r = o as Record<string, unknown>;
  return `{${Object.keys(r)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canonical(r[k])}`)
    .join(",")}}`;
}

function sign(priv: Uint8Array, it: SignIntent): string {
  return hex(p256.sign(sha256(new TextEncoder().encode(canonical(it))), priv).toCompactRawBytes());
}

/**
 * Máy chủ giả: `records` là các khoá của DID; khoá CUỐI là "owner mới nhất".
 * Không `?key=` ⇒ trả khoá cuối. Có `?key=` ⇒ trả đúng khoá đó, hoặc 404.
 * Ghi lại mọi URL để test khẳng định đúng tham số được gửi.
 */
function mockServer(records: Rec[]) {
  const urls: string[] = [];
  const spy = jest.spyOn(globalThis, "fetch").mockImplementation((async (input: unknown) => {
    const u = new URL(String(input));
    urls.push(String(input));
    const want = u.searchParams.get("key");
    const rec = want
      ? records.find((r) => r.public_key_hex.toLowerCase() === want.toLowerCase())
      : records[records.length - 1];
    if (!rec) {
      return new Response(JSON.stringify({ code: 1304, message: "KEY_NOT_FOUND" }), {
        status: 404,
        headers: { "Content-Type": "application/json" },
      });
    }
    return new Response(JSON.stringify({ code: 1000, message: "ok", result: rec }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }) as typeof fetch);
  return { spy, urls };
}

describe("PhoenixKeyVerifier — nhiều thiết bị cùng một DID", () => {
  it("(a) khoá owner thứ hai còn active (không phải mới nhất) ⇒ qua khi nêu public_key_hex", async () => {
    const phone = device();
    const laptop = device(); // mới nhất
    const { urls } = mockServer([
      { public_key_hex: phone.pubHex, key_role: "owner", status: "active" },
      { public_key_hex: laptop.pubHex, key_role: "owner", status: "active" },
    ]);
    const it = intent();
    const v = new PhoenixKeyVerifier({ phoenixkeyApiUrl: BASE });

    const out = await v.verifyIntent({
      user_did: DID,
      intent: it,
      signature: sign(phone.priv, it),
      public_key_hex: phone.pubHex,
    });
    expect(out).toMatchObject({ valid: true, user_did: DID });
    expect(urls[0]).toContain(`/pubkey?key=${phone.pubHex}`);
  });

  it("không nêu khoá ⇒ hành vi cũ giữ nguyên (khoá mới nhất, không có ?key=)", async () => {
    const phone = device();
    const laptop = device();
    const { urls } = mockServer([
      { public_key_hex: phone.pubHex, key_role: "owner", status: "active" },
      { public_key_hex: laptop.pubHex, key_role: "owner", status: "active" },
    ]);
    const it = intent();
    const v = new PhoenixKeyVerifier({ phoenixkeyApiUrl: BASE });

    await expect(
      v.verifyIntent({ user_did: DID, intent: it, signature: sign(laptop.priv, it) }),
    ).resolves.toMatchObject({ valid: true });
    expect(urls[0]).not.toContain("?key=");
  });

  it("(b) khoá đó đã thu hồi ⇒ trượt key_revoked dù chữ ký đúng toán học", async () => {
    const phone = device();
    const laptop = device();
    mockServer([
      {
        public_key_hex: phone.pubHex,
        key_role: "owner",
        status: "revoked",
        revoked_at: "2026-10-01T00:00:00Z",
      },
      { public_key_hex: laptop.pubHex, key_role: "owner", status: "active" },
    ]);
    const it = intent();
    const v = new PhoenixKeyVerifier({ phoenixkeyApiUrl: BASE });

    const out = await v.verifyIntent({
      user_did: DID,
      intent: it,
      signature: sign(phone.priv, it),
      public_key_hex: phone.pubHex,
    });
    expect(out.valid).toBe(false);
    expect(out.reason).toBe("key_revoked: 2026-10-01T00:00:00Z");
  });

  it("(c) ?key= trả 404 ⇒ trượt, KHÔNG rơi về khoá mới nhất", async () => {
    const stranger = device(); // không thuộc DID
    const laptop = device(); // khoá duy nhất của DID
    const { urls } = mockServer([{ public_key_hex: laptop.pubHex, key_role: "owner", status: "active" }]);
    const it = intent();
    const v = new PhoenixKeyVerifier({ phoenixkeyApiUrl: BASE });

    // Chữ ký của khoá lạ + gợi ý khoá lạ ⇒ 404 ⇒ trượt.
    const out = await v.verifyIntent({
      user_did: DID,
      intent: it,
      signature: sign(stranger.priv, it),
      public_key_hex: stranger.pubHex,
    });
    expect(out.valid).toBe(false);
    expect(out.reason).toMatch(/^resolve_failed/);
    expect(urls).toHaveLength(1); // không có lượt thứ hai hỏi "khoá mới nhất"

    // Chữ ký của khoá THẬT (laptop) nhưng gợi ý khoá lạ ⇒ vẫn trượt: không
    // được rơi về khoá mới nhất rồi thấy chữ ký khớp.
    const out2 = await v.verifyIntent({
      user_did: DID,
      intent: it,
      signature: sign(laptop.priv, it),
      public_key_hex: stranger.pubHex,
    });
    expect(out2.valid).toBe(false);
    expect(out2.reason).toMatch(/^resolve_failed/);
  });

  it("(d) bộ đệm khoá theo (did, khoá): hai thiết bị không lẫn nhau", async () => {
    const phone = device();
    const laptop = device();
    const { spy } = mockServer([
      { public_key_hex: phone.pubHex, key_role: "owner", status: "active" },
      { public_key_hex: laptop.pubHex, key_role: "owner", status: "active" },
    ]);
    const it = intent();
    const v = new PhoenixKeyVerifier({ phoenixkeyApiUrl: BASE, cacheTtlMs: 60_000 });

    const sigPhone = sign(phone.priv, it);
    const sigLaptop = sign(laptop.priv, it);

    // Nạp đệm cho điện thoại trước, rồi laptop: laptop KHÔNG được dùng mục của điện thoại.
    await expect(
      v.verifyIntent({ user_did: DID, intent: it, signature: sigPhone, public_key_hex: phone.pubHex }),
    ).resolves.toMatchObject({ valid: true });
    await expect(
      v.verifyIntent({ user_did: DID, intent: it, signature: sigLaptop, public_key_hex: laptop.pubHex }),
    ).resolves.toMatchObject({ valid: true });
    expect(spy).toHaveBeenCalledTimes(2);

    // Chéo: chữ ký điện thoại dưới gợi ý laptop phải trượt (mục đệm đúng khoá).
    await expect(
      v.verifyIntent({ user_did: DID, intent: it, signature: sigPhone, public_key_hex: laptop.pubHex }),
    ).resolves.toMatchObject({ valid: false, reason: "signature_invalid" });
    // Lần này trúng đệm ⇒ không thêm lượt mạng.
    expect(spy).toHaveBeenCalledTimes(2);

    // Đường "mới nhất" là mục đệm thứ ba, riêng.
    await v.verifyIntent({ user_did: DID, intent: it, signature: sigLaptop });
    expect(spy).toHaveBeenCalledTimes(3);
  });

  it("hex hoa / tiền tố 0x vẫn tra đúng một khoá và dùng chung một mục đệm", async () => {
    const phone = device();
    const laptop = device();
    const { spy, urls } = mockServer([
      { public_key_hex: phone.pubHex, key_role: "owner", status: "active" },
      { public_key_hex: laptop.pubHex, key_role: "owner", status: "active" },
    ]);
    const it = intent();
    const v = new PhoenixKeyVerifier({ phoenixkeyApiUrl: BASE, cacheTtlMs: 60_000 });
    const sig = sign(phone.priv, it);

    await expect(
      v.verifyIntent({ user_did: DID, intent: it, signature: sig, public_key_hex: "0x" + phone.pubHex.toUpperCase() }),
    ).resolves.toMatchObject({ valid: true });
    await v.verifyIntent({ user_did: DID, intent: it, signature: sig, public_key_hex: phone.pubHex });
    expect(spy).toHaveBeenCalledTimes(1);
    expect(urls[0]).toContain(`?key=${phone.pubHex}`);
  });

  it("khoá vai manager/viewer KHÔNG ký được intent dù còn active", async () => {
    const phone = device();
    const viewer = device();
    mockServer([
      { public_key_hex: phone.pubHex, key_role: "owner", status: "active" },
      { public_key_hex: viewer.pubHex, key_role: "viewer", status: "active" },
    ]);
    const it = intent();
    const v = new PhoenixKeyVerifier({ phoenixkeyApiUrl: BASE });

    const out = await v.verifyIntent({
      user_did: DID,
      intent: it,
      signature: sign(viewer.priv, it),
      public_key_hex: viewer.pubHex,
    });
    expect(out).toMatchObject({ valid: false, reason: "key_role_not_owner" });
  });

  it("máy chủ trả bản ghi của khoá KHÁC khoá đã hỏi ⇒ key_mismatch", async () => {
    const phone = device();
    const laptop = device();
    // Máy chủ lỗi: luôn trả laptop bất kể ?key=.
    jest.spyOn(globalThis, "fetch").mockImplementation((async () =>
      new Response(
        JSON.stringify({ code: 1000, result: { public_key_hex: laptop.pubHex, key_role: "owner", status: "active" } }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      )) as typeof fetch);
    const it = intent();
    const v = new PhoenixKeyVerifier({ phoenixkeyApiUrl: BASE });

    const out = await v.verifyIntent({
      user_did: DID,
      intent: it,
      signature: sign(laptop.priv, it),
      public_key_hex: phone.pubHex,
    });
    expect(out).toMatchObject({ valid: false, reason: "key_mismatch" });
  });

  it("resolveKey / resolvePubkey nhận khoá tuỳ chọn", async () => {
    const phone = device();
    const laptop = device();
    mockServer([
      { public_key_hex: phone.pubHex, key_role: "owner", status: "active" },
      { public_key_hex: laptop.pubHex, key_role: "owner", status: "active" },
    ]);
    const v = new PhoenixKeyVerifier({ phoenixkeyApiUrl: BASE });
    await expect(v.resolvePubkey(DID)).resolves.toBe(laptop.pubHex);
    await expect(v.resolvePubkey(DID, phone.pubHex)).resolves.toBe(phone.pubHex);
    await expect(v.resolveKey(DID, phone.pubHex)).resolves.toMatchObject({ status: "active" });
  });
});
