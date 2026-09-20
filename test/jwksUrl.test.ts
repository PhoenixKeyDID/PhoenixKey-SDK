/**
 * Cổng gác ĐỊA CHỈ JWKS mà `AppTokenVerifier` gọi tới khi dùng cấu hình mặc định.
 *
 * ## Vì sao có tệp này
 *
 * Mặc định cũ là gốc miền trần `https://api.phoenixkey.me`, ghép thành
 * `https://api.phoenixkey.me/.well-known/jwks.json`. Đo trên sản xuất
 * 2026-09-08:
 *
 * ```
 * GET https://api.phoenixkey.me/api/v1/.well-known/jwks.json → 200 {"keys":[…]}
 * GET https://api.phoenixkey.me/.well-known/jwks.json         → 404
 * ```
 *
 * Nghĩa là mọi bên thứ ba viết `new AppTokenVerifier()` — đúng như tài liệu bảo
 * — đều chết ở `jwks_fetch_failed` và KHÔNG kiểm được thẻ nào. Verify thẻ là
 * mắt cuối của luồng "quét bằng điện thoại, trang web có phiên", nên cả năng
 * lực ấy tối om với ai dùng mặc định. Toàn bộ 182 bài kiểm khi đó vẫn xanh: bộ
 * kiểm cũ luôn tiêm `fetch` giả, nên không bài nào từng nhìn tới ĐỊA CHỈ THẬT.
 *
 * Cổng này gác chuỗi địa chỉ, không gác tên hàm dựng địa chỉ.
 */

import {
  AppTokenVerifier,
  PhoenixKeyVerifier,
  DEFAULT_PHOENIXKEY_API_URL,
  JWKS_PATH,
} from "../src/verifier";

/** Bắt lấy URL mà lớp verifier thật sự gọi, không đoán từ cấu hình. */
async function fetchedUrls(v: AppTokenVerifier, token: string): Promise<string[]> {
  const seen: string[] = [];
  const real = globalThis.fetch;
  (globalThis as { fetch: unknown }).fetch = async (u: unknown) => {
    seen.push(String(u));
    return {
      ok: true,
      status: 200,
      json: async () => ({ keys: [] }),
    } as unknown as Response;
  };
  try {
    await v.verify(token, "did:phoenix:svc:test").catch(() => undefined);
  } finally {
    (globalThis as { fetch: unknown }).fetch = real;
  }
  return seen;
}

/** JWT 3 phần, alg EdDSA — đủ để đi qua cổng alg và tới bước tra JWKS. */
function tokenEdDSA(): string {
  const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
  return `${b64({ alg: "EdDSA", kid: "phoenixkey-ed25519-1" })}.${b64({ exp: 9_999_999_999 })}.AAAA`;
}

describe("địa chỉ JWKS mặc định", () => {
  it("GỒM context-path /api/v1 — gốc miền trần trả 404 trên sản xuất", () => {
    expect(DEFAULT_PHOENIXKEY_API_URL).toBe("https://api.phoenixkey.me/api/v1");
    // Ghim luôn mệnh đề, không chỉ ghim chuỗi: thiếu context-path là ca hỏng.
    expect(DEFAULT_PHOENIXKEY_API_URL).toContain("/api/v1");
    expect(DEFAULT_PHOENIXKEY_API_URL).not.toBe("https://api.phoenixkey.me");
  });

  it("AppTokenVerifier mặc định gọi ĐÚNG đường đang phục vụ", async () => {
    const seen = await fetchedUrls(new AppTokenVerifier(), tokenEdDSA());

    expect(seen).toEqual(["https://api.phoenixkey.me/api/v1/.well-known/jwks.json"]);
    // Đúng địa chỉ đã đo 404 — đừng bao giờ quay lại nó.
    expect(seen[0]).not.toBe("https://api.phoenixkey.me/.well-known/jwks.json");
  });

  it("hai lớp verifier khai CÙNG một gốc — lệch nhau là ca đã xảy ra một lần", async () => {
    // `PhoenixKeyVerifier` xưa nay đúng, `AppTokenVerifier` thì không. Hai lớp
    // cùng một kho, cùng một máy chủ, mà hai gốc khác nhau — không ai đọc chéo
    // được để phát hiện.
    const baseUrl = (new PhoenixKeyVerifier() as unknown as { phoenixkeyApiUrl: string })
      .phoenixkeyApiUrl;
    expect(baseUrl).toBe(DEFAULT_PHOENIXKEY_API_URL);
  });

  it("cấu hình tường minh vẫn thắng mặc định (bên tự dựng máy chủ)", async () => {
    const seen = await fetchedUrls(
      new AppTokenVerifier({ phoenixkeyApiUrl: "https://noi-bo.example/api/v1/" }),
      tokenEdDSA(),
    );
    expect(seen).toEqual([`https://noi-bo.example/api/v1${JWKS_PATH}`]);
  });
});

describe("JWKS hỏng thì phải nói ra chỗ sửa", () => {
  async function captureError(status: number, body: unknown): Promise<Error> {
    const real = globalThis.fetch;
    (globalThis as { fetch: unknown }).fetch = async () =>
      ({ ok: status < 400, status, json: async () => body }) as unknown as Response;
    try {
      await new AppTokenVerifier().verify(tokenEdDSA(), "did:phoenix:svc:test");
      throw new Error("đáng lẽ phải ném");
    } catch (e) {
      return e as Error;
    } finally {
      (globalThis as { fetch: unknown }).fetch = real;
    }
  }

  it("404 nêu ĐƯỜNG đã gọi và nghi phạm context-path", async () => {
    const err = await captureError(404, {});
    expect(err.message).toContain("https://api.phoenixkey.me/api/v1/.well-known/jwks.json");
    // Phải gác CHỮ của lời gợi ý, không gác chuỗi "/api/v1" — chuỗi đó đã nằm
    // sẵn trong URL in ra ở trên, nên gác nó là gác chính mình. (Đột biến "bỏ
    // phần gợi ý khỏi lời nhắn" chạy qua bản trước mà không đỏ — đo 2026-09-08.)
    expect(err.message).toContain("context-path");
    expect(err.message).toContain("phoenixkeyApiUrl");
    // Bản cũ chỉ nói "JWKS fetch failed: HTTP 404" — người tích hợp dùng mặc
    // định thì không có manh mối nào để lần ra.
    expect(err.message).not.toMatch(/^JWKS fetch failed: HTTP 404$/);
  });

  it("200 mà thân không có mảng keys ⇒ ném, KHÔNG đệm cái hỏng suốt một giờ", async () => {
    const err = await captureError(200, { message: "trang lỗi của proxy" });
    expect((err as { code?: string }).code).toBe("jwks_fetch_failed");
    expect(err.message).toContain("keys");
  });
});

/**
 * ── BẢNG ĐỘT BIẾN (chạy tay 2026-09-08) ──────────────────────────────────────
 *
 * | # | Mệnh đề gỡ                                                   | Bài đỏ                                              |
 * |---|--------------------------------------------------------------|-----------------------------------------------------|
 * | 8 | `DEFAULT_PHOENIXKEY_API_URL` bỏ `/api/v1` (về mặc định cũ)    | cả 3 bài đầu của "địa chỉ JWKS mặc định" + 404 nêu…  |
 * | 9 | Nhánh `!Array.isArray(jwks?.keys)` trong `getJwks`            | "200 mà thân không có mảng keys ⇒ ném…"             |
 * |10 | Phần nêu context-path trong lời nhắn lỗi 404                  | "404 nêu ĐƯỜNG đã gọi và nghi phạm context-path"    |
 *
 * Không lượt nào làm đỏ một bài KHÔNG liên quan.
 *
 * ⚠ Lượt 10 lúc đầu KHÔNG đỏ bài nào: bài kiểm khi ấy soi `toContain("/api/v1")`,
 * mà chuỗi đó đã nằm sẵn trong URL được in ra ngay phía trước — cổng đang soi
 * chính mình. Nay soi "context-path" + "phoenixkeyApiUrl", là chữ chỉ có trong
 * phần gợi ý. Ghi lại vì đây là ca gác-vị-trí trá hình.
 */
