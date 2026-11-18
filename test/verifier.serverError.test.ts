import { PhoenixKeyVerifier } from "../src/verifier";
import { PhoenixKeyError, SignIntent } from "../src/types";

const BASE = "https://api.example.test";
const DID = "did:phoenix:aaaaaaaaaaaaa:" + "0".repeat(64);

afterEach(() => {
  jest.restoreAllMocks();
});

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

/**
 * Máy chủ giả trả ĐÚNG một phản hồi lỗi cho mọi lượt tra pubkey.
 * Hai phong bì thật của máy chủ (đo trên api.phoenixkey.me, backend PR #755):
 * - 400 `{"code":2094,"message":"DID is missing its 64-hex segment; ..."}`
 * - 404 `{"code":3002,"message":"Authorized key not found"}`
 */
function mockError(status: number, body: string, contentType = "application/json") {
  return jest.spyOn(globalThis, "fetch").mockImplementation((async () =>
    new Response(body, { status, headers: { "Content-Type": contentType } })) as typeof fetch);
}

const MSG_2094 = "DID is missing its 64-hex segment; send the full did:phoenix:<13 chars>:<64 hex>";
const MSG_3002 = "Authorized key not found";

describe("PhoenixKeyVerifier — giữ mã lỗi máy chủ khi tra pubkey thất bại (#47)", () => {
  it("400 code 2094 ⇒ lỗi mang rawCode 2094 và đúng câu của máy chủ", async () => {
    mockError(400, JSON.stringify({ code: 2094, message: MSG_2094 }));
    const v = new PhoenixKeyVerifier({ phoenixkeyApiUrl: BASE });

    await expect(v.resolveKey(DID)).rejects.toMatchObject({
      name: "PhoenixKeyError",
      status: 400,
      code: "resolve_failed", // code chuỗi giữ nguyên nghĩa cũ
      rawCode: 2094,
      message: MSG_2094, // nguyên văn, không thêm bớt
    });
  });

  it("404 code 3002 ⇒ lỗi mang rawCode 3002 và đúng câu của máy chủ", async () => {
    mockError(404, JSON.stringify({ code: 3002, message: MSG_3002 }));
    const v = new PhoenixKeyVerifier({ phoenixkeyApiUrl: BASE });

    await expect(v.resolvePubkey(DID)).rejects.toMatchObject({
      status: 404,
      code: "resolve_failed",
      rawCode: 3002,
      message: MSG_3002,
    });
  });

  it("verifyIntent: lý do trượt mang câu của máy chủ (resolve_failed: <câu>)", async () => {
    mockError(400, JSON.stringify({ code: 2094, message: MSG_2094 }));
    const v = new PhoenixKeyVerifier({ phoenixkeyApiUrl: BASE });

    const out = await v.verifyIntent({ user_did: DID, intent: intent(), signature: "00" });
    expect(out).toMatchObject({ valid: false, reason: `resolve_failed: ${MSG_2094}` });
  });

  it("thân 400 không phải JSON ⇒ resolve_failed như cũ, không bịa mã", async () => {
    mockError(400, "<html>Bad Request</html>", "text/html");
    const v = new PhoenixKeyVerifier({ phoenixkeyApiUrl: BASE });

    // Phải ném đúng PhoenixKeyError để đọc rawCode — không chỉ so chuỗi.
    const err = await v.resolveKey(DID).then(
      () => { throw new Error("expected rejection"); },
      (e: unknown) => e as PhoenixKeyError,
    );
    expect(err).toBeInstanceOf(PhoenixKeyError);
    expect(err.status).toBe(400);
    expect(err.code).toBe("resolve_failed");
    expect(err.rawCode).toBeUndefined(); // không có phong bì ⇒ không có mã
    expect(err.message).toBe("PhoenixKey pubkey lookup failed: 400");
  });

  it("phong bì JSON mà code không phải số ⇒ không bịa mã, giữ thông điệp cũ", async () => {
    mockError(500, JSON.stringify({ code: "oops", message: "boom" }));
    const v = new PhoenixKeyVerifier({ phoenixkeyApiUrl: BASE });

    const err = await v.resolveKey(DID).then(
      () => { throw new Error("expected rejection"); },
      (e: unknown) => e as PhoenixKeyError,
    );
    expect(err).toBeInstanceOf(PhoenixKeyError);
    expect(err.status).toBe(500);
    expect(err.code).toBe("resolve_failed");
    expect(err.rawCode).toBeUndefined();
    expect(err.message).toBe("PhoenixKey pubkey lookup failed: 500");
  });
});
