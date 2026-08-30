import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";
import { PhoenixKeyVerifier } from "../src/verifier";
import { PhoenixKeyError } from "../src/types";

const BASE = "https://api.example.test";
const DID = "did:phoenix:aaaaaaaaaaaaa:" + "0".repeat(64);

afterEach(() => {
  jest.restoreAllMocks();
});

function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

/** Ký thật bằng P-256 để ca "hợp lệ" không đi qua nhánh chữ ký sai. */
function signedProof() {
  const priv = p256.utils.randomPrivateKey();
  const pubHex = bytesToHex(p256.getPublicKey(priv));
  const challenge = "chal-1";
  const domain = "example.test";
  const timestamp = Math.floor(Date.now() / 1000);
  const msg = `${challenge}:${domain}:${timestamp}`;
  const sig = p256.sign(sha256(new TextEncoder().encode(msg)), priv);
  return {
    pubHex,
    req: { user_did: DID, signature: bytesToHex(sig.toCompactRawBytes()), challenge, domain, timestamp },
  };
}

/** Máy chủ trả 200 kèm status cho CẢ khoá đã thu hồi — đó là hành vi cố ý. */
function mockPubkeyResponse(result: Record<string, unknown>) {
  return jest.spyOn(globalThis, "fetch").mockImplementation((async () =>
    new Response(JSON.stringify({ code: 1000, message: "ok", result }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    })) as typeof fetch);
}

describe("PhoenixKeyVerifier — trạng thái khoá", () => {
  it("chấp nhận chữ ký khi khoá còn active", async () => {
    const { pubHex, req } = signedProof();
    mockPubkeyResponse({ public_key_hex: pubHex, key_role: "owner", status: "active", revoked_at: null });

    const v = new PhoenixKeyVerifier({ phoenixkeyApiUrl: BASE });
    await expect(v.verifyAuthProof(req)).resolves.toMatchObject({ valid: true, user_did: DID });
  });

  it("TỪ CHỐI chữ ký đúng về mặt toán học nếu khoá đã bị thu hồi", async () => {
    const { pubHex, req } = signedProof();
    mockPubkeyResponse({
      public_key_hex: pubHex,
      key_role: "owner",
      status: "revoked",
      revoked_at: "2026-08-01T00:00:00Z",
    });

    const v = new PhoenixKeyVerifier({ phoenixkeyApiUrl: BASE });
    const out = await v.verifyAuthProof(req);
    expect(out.valid).toBe(false);
    expect(out.reason).toBe("key_revoked: 2026-08-01T00:00:00Z");
  });

  it("thiếu trường status thì coi như KHÔNG dùng được, không coi như active", async () => {
    const { pubHex, req } = signedProof();
    mockPubkeyResponse({ public_key_hex: pubHex, key_role: "owner" });

    const v = new PhoenixKeyVerifier({ phoenixkeyApiUrl: BASE });
    const out = await v.verifyAuthProof(req);
    expect(out.valid).toBe(false);
    expect(out.reason).toBe("key_revoked");
  });
});

describe("PhoenixKeyVerifier — resolvePubkey / resolveKey", () => {
  it("resolvePubkey ném lỗi key_revoked thay vì trả hex của khoá đã thu hồi", async () => {
    const { pubHex } = signedProof();
    mockPubkeyResponse({
      public_key_hex: pubHex,
      key_role: "owner",
      status: "revoked",
      revoked_at: "2026-08-01T00:00:00Z",
    });

    const v = new PhoenixKeyVerifier({ phoenixkeyApiUrl: BASE });
    await expect(v.resolvePubkey(DID)).rejects.toBeInstanceOf(PhoenixKeyError);
    await expect(v.resolvePubkey(DID)).rejects.toMatchObject({ code: "key_revoked" });
  });

  it("resolveKey trả nguyên bản ghi, kể cả khoá đã thu hồi — bên gọi tự quyết", async () => {
    const { pubHex } = signedProof();
    mockPubkeyResponse({
      public_key_hex: pubHex,
      key_role: "owner",
      status: "revoked",
      revoked_at: "2026-08-01T00:00:00Z",
    });

    const v = new PhoenixKeyVerifier({ phoenixkeyApiUrl: BASE });
    await expect(v.resolveKey(DID)).resolves.toMatchObject({
      public_key_hex: pubHex,
      status: "revoked",
      revoked_at: "2026-08-01T00:00:00Z",
    });
  });

  it("cacheTtlMs=0 thì mỗi lần verify là một lượt gọi mạng — thu hồi lan ngay", async () => {
    const { pubHex, req } = signedProof();
    const spy = mockPubkeyResponse({ public_key_hex: pubHex, key_role: "owner", status: "active" });

    const v = new PhoenixKeyVerifier({ phoenixkeyApiUrl: BASE, cacheTtlMs: 0 });
    await v.verifyAuthProof(req);
    await v.verifyAuthProof(req);
    expect(spy).toHaveBeenCalledTimes(2);
  });
});
