/**
 * `AuthModule.exchange()` — đổi thẻ phiên 24 giờ lấy thẻ app 15 phút.
 *
 * Ba điều được chốt ở đây, mỗi điều một lý do cụ thể:
 *  1. thẻ phiên KHÔNG bao giờ vào URL (lịch sử trình duyệt / Referer / log proxy);
 *  2. lỗi 401 / 403 / 400 phân biệt được, để bên tích hợp biết khi nào cho đăng
 *     nhập lại và khi nào phải sửa cấu hình app đích;
 *  3. hạn dùng đọc từ máy chủ, không phải hằng số trong mã.
 */

import { AuthModule } from "../src/auth";
import { PhoenixKeyError } from "../src/types";

const BASE = "https://api.example.test";
const SESSION_TOKEN = "sess.THE-SECRET-SESSION-TOKEN.xyz";
const AUD = "did:phoenix:abcdefghijklm:" + "ab".repeat(32);
const REDIRECT = "https://partner.example/callback";

function mockFetch(impl: (url: string, init: RequestInit) => Promise<Response>) {
  return jest.spyOn(globalThis, "fetch").mockImplementation(impl as typeof fetch);
}

function b64url(obj: unknown): string {
  return Buffer.from(JSON.stringify(obj), "utf8").toString("base64url");
}

/** Thẻ giả có đúng ba phần — chỉ dùng để đọc claim `exp`, không ký thật. */
function fakeJwt(payload: Record<string, unknown>): string {
  return `${b64url({ alg: "EdDSA", kid: "phoenixkey-ed25519-1" })}.${b64url(payload)}.c2ln`;
}

function okResponse(body: Record<string, unknown>) {
  return new Response(JSON.stringify({ code: 1000, message: "Token exchanged", result: body }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

function errResponse(code: number, status: number, message = "boom") {
  return new Response(JSON.stringify({ code, message }), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function newModule() {
  return new AuthModule(BASE, BASE, "partner.example", () => null);
}

afterEach(() => {
  jest.restoreAllMocks();
});

// ─────────────────────────────────────────────────────────────────────────────
// 1. Thẻ phiên đi trong THÂN yêu cầu, không bao giờ trong URL
// ─────────────────────────────────────────────────────────────────────────────

describe("exchange() — thẻ phiên không bao giờ nằm trong URL", () => {
  it("POST tới /auth/token/exchange với URL trần, thẻ nằm trong thân", async () => {
    let seenUrl = "";
    let seenMethod = "";
    let seenBody = "";
    mockFetch(async (url, init) => {
      seenUrl = String(url);
      seenMethod = String(init.method);
      seenBody = String(init.body);
      return okResponse({
        app_token: fakeJwt({ exp: Math.floor(Date.now() / 1000) + 900 }),
        user_did: "did:phoenix:x:y",
      });
    });

    await newModule().exchange({
      sessionToken: SESSION_TOKEN,
      aud: AUD,
      redirectUri: REDIRECT,
    });

    // Cốt lõi: chuỗi thẻ không xuất hiện ở BẤT KỲ đâu trong URL.
    expect(seenUrl).not.toContain(SESSION_TOKEN);
    // Và không phải vì thẻ bị mã hoá URL rồi lẻn vào — URL không có phần truy vấn nào.
    expect(seenUrl).toBe(`${BASE}/auth/token/exchange`);
    expect(seenUrl).not.toContain("?");
    expect(seenMethod).toBe("POST");

    // Thẻ phải thật sự được gửi — nếu không, bài trên xanh một cách rỗng.
    expect(JSON.parse(seenBody)).toEqual({
      session_token: SESSION_TOKEN,
      aud: AUD,
      redirect_uri: REDIRECT,
    });
  });

  it("nonce tuỳ chọn: gửi khi có, vắng hẳn khỏi thân khi không truyền", async () => {
    const bodies: string[] = [];
    mockFetch(async (_url, init) => {
      bodies.push(String(init.body));
      return okResponse({
        app_token: fakeJwt({ exp: Math.floor(Date.now() / 1000) + 900 }),
        user_did: "did:phoenix:x:y",
      });
    });

    const mod = newModule();
    await mod.exchange({ sessionToken: SESSION_TOKEN, aud: AUD, redirectUri: REDIRECT });
    await mod.exchange({
      sessionToken: SESSION_TOKEN,
      aud: AUD,
      redirectUri: REDIRECT,
      nonce: "n-1",
    });

    expect(Object.keys(JSON.parse(bodies[0]))).not.toContain("nonce");
    expect(JSON.parse(bodies[1]).nonce).toBe("n-1");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. Lỗi phân biệt được
// ─────────────────────────────────────────────────────────────────────────────

describe("exchange() — lỗi 401 / 403 / 400 phân biệt được", () => {
  it("401 UNAUTHORIZED (1304) → code 'unauthorized' — cho đăng nhập lại", async () => {
    mockFetch(async () => errResponse(1304, 401, "session token revoked (epoch stale)"));
    await expect(
      newModule().exchange({ sessionToken: SESSION_TOKEN, aud: AUD, redirectUri: REDIRECT }),
    ).rejects.toMatchObject({ code: "unauthorized", status: 401 });
  });

  it("403 SIGNATURE_INVALID (1403) → code 'signature_invalid' — thẻ hỏng/hết hạn", async () => {
    mockFetch(async () => errResponse(1403, 403, "Invalid or expired JWT"));
    await expect(
      newModule().exchange({ sessionToken: SESSION_TOKEN, aud: AUD, redirectUri: REDIRECT }),
    ).rejects.toMatchObject({ code: "signature_invalid", status: 403 });
  });

  it("400 REDIRECT_URI_MISMATCH (1331) → code 'redirect_uri_mismatch' — lỗi cấu hình, KHÁC hết hạn", async () => {
    mockFetch(async () => errResponse(1331, 400, "redirect_uri not in aud's serviceEndpoint[]"));
    const err = await newModule()
      .exchange({ sessionToken: SESSION_TOKEN, aud: AUD, redirectUri: REDIRECT })
      .catch((e) => e as PhoenixKeyError);

    expect(err).toBeInstanceOf(PhoenixKeyError);
    expect((err as PhoenixKeyError).code).toBe("redirect_uri_mismatch");
    // Điểm của cả bài: KHÔNG lẫn với nhóm "đăng nhập lại đi".
    expect((err as PhoenixKeyError).code).not.toBe("unauthorized");
    expect((err as PhoenixKeyError).code).not.toBe("signature_invalid");
  });

  it("404 SERVICE_DID_NOT_FOUND (1330) → code 'service_did_not_found'", async () => {
    mockFetch(async () => errResponse(1330, 404, "aud has no published service endpoints"));
    await expect(
      newModule().exchange({ sessionToken: SESSION_TOKEN, aud: AUD, redirectUri: REDIRECT }),
    ).rejects.toMatchObject({ code: "service_did_not_found" });
  });

  it("429 RATE_LIMITED (1332) → code 'rate_limited'", async () => {
    mockFetch(async () => errResponse(1332, 429, "Max 10 exchanges per minute per session_token"));
    await expect(
      newModule().exchange({ sessionToken: SESSION_TOKEN, aud: AUD, redirectUri: REDIRECT }),
    ).rejects.toMatchObject({ code: "rate_limited" });
  });

  it("thông báo lỗi không mang chuỗi thẻ phiên ra ngoài", async () => {
    mockFetch(async () => errResponse(1304, 401, "unauthorized"));
    const err = await newModule()
      .exchange({ sessionToken: SESSION_TOKEN, aud: AUD, redirectUri: REDIRECT })
      .catch((e) => e as PhoenixKeyError);
    expect((err as PhoenixKeyError).message).not.toContain(SESSION_TOKEN);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. Hạn dùng đọc từ máy chủ, không viết cứng
// ─────────────────────────────────────────────────────────────────────────────

describe("exchange() — expiresIn đọc từ phản hồi máy chủ", () => {
  it("suy từ claim `exp` máy chủ đã ký — 1800s, KHÔNG phải hằng số 900", async () => {
    const now = Math.floor(Date.now() / 1000);
    mockFetch(async () =>
      okResponse({ app_token: fakeJwt({ exp: now + 1800 }), user_did: "did:phoenix:x:y" }),
    );

    const res = await newModule().exchange({
      sessionToken: SESSION_TOKEN,
      aud: AUD,
      redirectUri: REDIRECT,
    });

    expect(res.expiresAt).toBe(now + 1800);
    expect(res.expiresIn).toBeGreaterThan(1700);
    expect(res.expiresIn).toBeLessThanOrEqual(1800);
    // Chốt cứng: giá trị TTL mặc định của máy chủ không được lọt vào như hằng số.
    expect(res.expiresIn).not.toBe(900);
  });

  it("đổi TTL phía máy chủ thì expiresIn đổi theo, SDK không phải phát hành lại", async () => {
    const now = Math.floor(Date.now() / 1000);
    const seen: number[] = [];
    for (const ttl of [900, 60, 3600]) {
      mockFetch(async () =>
        okResponse({ app_token: fakeJwt({ exp: now + ttl }), user_did: "did:phoenix:x:y" }),
      );
      const res = await newModule().exchange({
        sessionToken: SESSION_TOKEN,
        aud: AUD,
        redirectUri: REDIRECT,
      });
      seen.push(res.expiresAt - now);
      jest.restoreAllMocks();
    }
    expect(seen).toEqual([900, 60, 3600]);
  });

  it("trường `expires_in` tường minh của máy chủ thắng claim `exp`", async () => {
    const now = Math.floor(Date.now() / 1000);
    mockFetch(async () =>
      okResponse({
        app_token: fakeJwt({ exp: now + 1800 }),
        user_did: "did:phoenix:x:y",
        expires_in: 300,
      }),
    );
    const res = await newModule().exchange({
      sessionToken: SESSION_TOKEN,
      aud: AUD,
      redirectUri: REDIRECT,
    });
    expect(res.expiresIn).toBe(300);
    expect(res.expiresAt).toBe(now + 300);
  });

  it("không có `expires_in` lẫn `exp` → ném 'malformed_token', KHÔNG đoán bừa một con số", async () => {
    mockFetch(async () =>
      okResponse({ app_token: fakeJwt({ sub: "did:phoenix:x:y" }), user_did: "did:phoenix:x:y" }),
    );
    await expect(
      newModule().exchange({ sessionToken: SESSION_TOKEN, aud: AUD, redirectUri: REDIRECT }),
    ).rejects.toMatchObject({ code: "malformed_token" });
  });

  it("thiếu hẳn app_token trong phản hồi → ném 'malformed_token'", async () => {
    mockFetch(async () => okResponse({ user_did: "did:phoenix:x:y" }));
    await expect(
      newModule().exchange({ sessionToken: SESSION_TOKEN, aud: AUD, redirectUri: REDIRECT }),
    ).rejects.toBeInstanceOf(PhoenixKeyError);
  });

  it("trả lại app_token + user_did nguyên vẹn", async () => {
    const token = fakeJwt({ exp: Math.floor(Date.now() / 1000) + 900 });
    mockFetch(async () => okResponse({ app_token: token, user_did: "did:phoenix:aa:bb" }));
    const res = await newModule().exchange({
      sessionToken: SESSION_TOKEN,
      aud: AUD,
      redirectUri: REDIRECT,
    });
    expect(res.appToken).toBe(token);
    expect(res.userDid).toBe("did:phoenix:aa:bb");
  });
});
