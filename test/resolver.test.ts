/**
 * `ResolverModule` — tra DID theo W3C + JWKS.
 *
 * Bốn điều được chốt ở đây:
 *  1. hai đường `/identifiers/*` KHÔNG bọc `{code,message,result}` — phong bì
 *     ba phần phải đi thẳng qua bộ lấy dữ liệu dùng chung mà không hỏng;
 *  2. 400 / 404 / 410 / 501 là KẾT QUẢ, trả về phong bì, KHÔNG ném;
 *  3. "đã khai tử" phân biệt bằng `didDocumentMetadata.deactivated`, vì mã
 *     `error` giống hệt ca "chưa từng tồn tại";
 *  4. lỗi thật (mạng, 406, 5xx trần) vẫn ném — không bị nuốt thành phong bì.
 */

import {
  ResolverModule,
  isDeactivated,
  isResolved,
  DidResolutionResult,
} from "../src/resolver";
import { PhoenixKeyError } from "../src/types";

const BASE = "https://api.example.test/api/v1";
const DID = "did:phoenix:aaaaaaahl4nn6:" + "cd".repeat(32);
const HASH = "16".repeat(32); // 64 ký tự hex

const calls: string[] = [];

function envelope(over: Partial<DidResolutionResult> = {}): DidResolutionResult {
  return {
    didDocument: null,
    didResolutionMetadata: {},
    ...over,
  };
}

function mockRaw(status: number, body: unknown) {
  calls.length = 0;
  return jest.spyOn(globalThis, "fetch").mockImplementation((async (url: string) => {
    calls.push(String(url));
    return new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/did-resolution+json" },
    });
  }) as unknown as typeof fetch);
}

const mod = () => new ResolverModule(BASE);

const OK_DOC = {
  "@context": ["https://www.w3.org/ns/did/v1"],
  id: DID,
  controller: DID,
  verificationMethod: [
    { id: `${DID}#key-1`, type: "Ed25519VerificationKey2020", controller: DID, publicKeyHex: "ab" },
  ],
  authentication: [`${DID}#key-1`],
  assertionMethod: [`${DID}#key-1`],
  capabilityInvocation: [`${DID}#key-1`],
  service: [{ id: `${DID}#wallet`, type: "CardanoWallet", serviceEndpoint: "addr_test1w" }],
};

afterEach(() => {
  jest.restoreAllMocks();
});

describe("ResolverModule — tuyến đường + Accept", () => {
  it("resolve hits /identifiers/{did} với DID được mã hoá", async () => {
    mockRaw(200, envelope({ didDocument: OK_DOC }));
    await mod().resolve(DID);
    expect(calls[0]).toBe(`${BASE}/identifiers/${encodeURIComponent(DID)}`);
    expect(calls[0]).toContain("did%3Aphoenix%3A");
  });

  it("resolveByHash hits /identifiers/hash/{hashHex}", async () => {
    mockRaw(200, envelope({ didDocument: OK_DOC }));
    await mod().resolveByHash(HASH);
    expect(calls[0]).toBe(`${BASE}/identifiers/hash/${HASH}`);
  });

  it("getJwks hits /.well-known/jwks.json", async () => {
    mockRaw(200, { keys: [{ kty: "OKP", crv: "Ed25519", x: "abc", use: "sig", alg: "EdDSA", kid: "k1" }] });
    const jwks = await mod().getJwks();
    expect(calls[0]).toBe(`${BASE}/.well-known/jwks.json`);
    // Thân JWKS không có bọc `{code,...}` — nó phải qua nguyên hình dạng.
    expect(jwks.keys[0].kid).toBe("k1");
    expect(jwks.keys[0].crv).toBe("Ed25519");
  });

  it("versionTime chỉ vào URL khi được truyền", async () => {
    const f = mockRaw(200, envelope({ didDocument: OK_DOC }));
    const m = mod();
    await m.resolve(DID);
    await m.resolve(DID, { versionTime: "2026-01-15T10:30:00Z" });
    expect(calls[0]).not.toContain("versionTime");
    expect(calls[1]).toContain("?versionTime=2026-01-15T10%3A30%3A00Z");

    // Gửi đúng media type resolver phục vụ — Accept sai là 406, không phải phong bì.
    const headers = (f.mock.calls[0][1] as RequestInit).headers as Record<string, string>;
    expect(headers.Accept).toBe("application/did-resolution+json");
  });
});

describe("ResolverModule — phong bì đi thẳng, không bị bóc như DataResponse", () => {
  it("200 trả đủ ba phần, kể cả service[]", async () => {
    mockRaw(
      200,
      envelope({
        didDocument: OK_DOC,
        didResolutionMetadata: { contentType: "application/did+ld+json" },
        didDocumentMetadata: { created: "2026-07-25T10:00:00Z", deactivated: false, versionId: "tx1" },
      }),
    );
    const res = await mod().resolve(DID);

    expect(isResolved(res)).toBe(true);
    expect(res.didDocument!.id).toBe(DID);
    expect(res.didDocument!.service![0].serviceEndpoint).toBe("addr_test1w");
    expect(res.didResolutionMetadata.contentType).toBe("application/did+ld+json");
    expect(res.didDocumentMetadata!.versionId).toBe("tx1");
  });

  it("lượt point-in-time không mang service[] — đó là chủ ý, không phải thiếu dữ liệu", async () => {
    const { service, ...noService } = OK_DOC;
    void service;
    mockRaw(200, envelope({ didDocument: noService, didDocumentMetadata: { versionTime: "2026-01-15T10:30:00Z" } }));
    const res = await mod().resolve(DID, { versionTime: "2026-01-15T10:30:00Z" });

    expect(isResolved(res)).toBe(true);
    // Đủ khoá để xác minh chữ ký cũ…
    expect(res.didDocument!.verificationMethod).toHaveLength(1);
    // …nhưng KHÔNG kèm địa chỉ ví.
    expect(res.didDocument!.service).toBeUndefined();
  });
});

describe("ResolverModule — 400/404/410/501 là KẾT QUẢ, không phải sự cố", () => {
  it("404 notFound trả phong bì, không ném", async () => {
    mockRaw(404, envelope({ didResolutionMetadata: { error: "notFound", errorMessage: "no such DID" } }));
    const res = await mod().resolve(DID);
    expect(isResolved(res)).toBe(false);
    expect(res.didResolutionMetadata.error).toBe("notFound");
    expect(isDeactivated(res)).toBe(false);
  });

  it("410 đã khai tử: CÙNG mã error 'notFound', phân biệt bằng deactivated", async () => {
    mockRaw(
      410,
      envelope({
        didResolutionMetadata: { error: "notFound" },
        didDocumentMetadata: { deactivated: true },
      }),
    );
    const res = await mod().resolve(DID);

    expect(res.didResolutionMetadata.error).toBe("notFound");
    // Điểm của cả bài: bắt theo `error` thôi thì 410 lẫn với 404, và người
    // dùng nhận "không tìm thấy" cho một danh tính đã tự khai tử.
    expect(isDeactivated(res)).toBe(true);
  });

  it("400 invalidDid và 501 methodNotSupported cũng trả phong bì", async () => {
    mockRaw(400, envelope({ didResolutionMetadata: { error: "invalidDid" } }));
    expect((await mod().resolve("did:bogus")).didResolutionMetadata.error).toBe("invalidDid");

    jest.restoreAllMocks();
    mockRaw(501, envelope({ didResolutionMetadata: { error: "methodNotSupported" } }));
    const res = await mod().resolve("did:ethr:0xabc");
    expect(res.didResolutionMetadata.error).toBe("methodNotSupported");
    expect(isResolved(res)).toBe(false);
  });

  it("resolveByHash cũng theo cùng luật", async () => {
    mockRaw(404, envelope({ didResolutionMetadata: { error: "notFound" } }));
    const res = await mod().resolveByHash(HASH);
    expect(res.didResolutionMetadata.error).toBe("notFound");
  });
});

describe("ResolverModule — lỗi thật vẫn ném, không bị nuốt", () => {
  it("406 Accept sai: thân là bọc {code,...}, KHÔNG phải phong bì → ném 'not_acceptable'", async () => {
    mockRaw(406, { code: 1305, message: "Accept must include application/did-resolution+json" });
    const err = await mod()
      .resolve(DID)
      .catch((e) => e as PhoenixKeyError);

    expect(err).toBeInstanceOf(PhoenixKeyError);
    expect((err as PhoenixKeyError).code).toBe("not_acceptable");
    expect((err as PhoenixKeyError).status).toBe(406);
  });

  it("500 không kèm phong bì → ném, không giả vờ là 'notFound'", async () => {
    mockRaw(500, { message: "boom" });
    await expect(mod().resolve(DID)).rejects.toBeInstanceOf(PhoenixKeyError);
  });

  it("mạng đứt → ném 'network_error', không trả phong bì rỗng", async () => {
    jest.spyOn(globalThis, "fetch").mockImplementation((async () => {
      throw new Error("socket hang up");
    }) as unknown as typeof fetch);
    await expect(mod().resolve(DID)).rejects.toMatchObject({ code: "network_error" });
  });

  it("hashHex sai khuôn → 9800 'enum_invalid_value', không phải 'notFound'", async () => {
    mockRaw(400, { code: 9800, message: "hashHex must be 64 hex characters" });
    await expect(mod().resolveByHash("zz")).rejects.toMatchObject({
      code: "enum_invalid_value",
    });
  });
});
