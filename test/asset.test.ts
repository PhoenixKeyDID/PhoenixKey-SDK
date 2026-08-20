import {
  ASSET_CLASSES,
  ASSET_ERROR_CODES,
  AssetModule,
  buildAssetMintChallenge,
  isAllowedAssetClass,
  LOCATION_PROOF_MAX_LENGTH,
} from "../src/asset";
import { PhoenixKeyError } from "../src/types";

const BASE = "https://api.example.test";

// ─── Vectors ─────────────────────────────────────────────────────────────────
// Mọi chuỗi hex dưới đây là LITERAL, sinh từ một bản dựng lại CanonicalMessage
// bằng Python theo đúng mã Java (AssetCanonical.java + CanonicalMessage.java),
// KHÔNG phải do mã TypeScript đang kiểm tự tính ra. Test tự-nhất-quán (gọi lại
// chính biểu thức mà hàm dùng) không chứng minh được hợp đồng với backend.

const OWNER_DID = "did:phoenix:mfx7q2wl3k5np:" + "9f".repeat(32);
const PHYSICAL_ID_HASH = "3a".repeat(32);

/** ownerDid, physicalIdHash, assetClass="tree", locationProof="zoneA", nonce="n1" */
const VECTOR_BASE =
  "50484f454e49584b45595f41535345545f4d494e543a0000005a6469643a70686f656e69783a6d6678377132776c336b356e703a3966396639663966396639663966396639663966396639663966396639663966396639663966396639663966396639663966396639663966396639663966396600000040336133613361336133613361336133613361336133613361336133613361336133613361336133613361336133613361336133613361336133613361336133610000000474726565000000013100000005" +
  "7a6f6e6541000000026e31";

/** Như trên nhưng locationProof = null (vắng mặt) → cờ "0", giá trị rỗng. */
const VECTOR_LOCATION_NULL =
  "50484f454e49584b45595f41535345545f4d494e543a0000005a6469643a70686f656e69783a6d6678377132776c336b356e703a3966396639663966396639663966396639663966396639663966396639663966396639663966396639663966396639663966396639663966396639663966396600000040336133613361336133613361336133613361336133613361336133613361336133613361336133613361336133613361336133613361336133613361336133610000000474726565000000013000000000000000026e31";

/** locationProof = "" (có mặt, rỗng) → cờ "1", giá trị rỗng. */
const VECTOR_LOCATION_EMPTY =
  "50484f454e49584b45595f41535345545f4d494e543a0000005a6469643a70686f656e69783a6d6678377132776c336b356e703a3966396639663966396639663966396639663966396639663966396639663966396639663966396639663966396639663966396639663966396639663966396600000040336133613361336133613361336133613361336133613361336133613361336133613361336133613361336133613361336133613361336133613361336133610000000474726565000000013100000000000000026e31";

/** locationProof = "null" (chuỗi bốn chữ cái) → cờ "1", giá trị "null". */
const VECTOR_LOCATION_LITERAL_NULL =
  "50484f454e49584b45595f41535345545f4d494e543a0000005a6469643a70686f656e69783a6d6678377132776c336b356e703a3966396639663966396639663966396639663966396639663966396639663966396639663966396639663966396639663966396639663966396639663966396600000040336133613361336133613361336133613361336133613361336133613361336133613361336133613361336133613361336133613361336133613361336133610000000474726565000000013100000004" +
  "6e756c6c000000026e31";

/** locationProof = "zoneA:n1", nonce = "n2" — nửa kia của cặp nhập nhằng khung. */
const VECTOR_FRAME_A =
  "50484f454e49584b45595f41535345545f4d494e543a0000005a6469643a70686f656e69783a6d6678377132776c336b356e703a3966396639663966396639663966396639663966396639663966396639663966396639663966396639663966396639663966396639663966396639663966396600000040336133613361336133613361336133613361336133613361336133613361336133613361336133613361336133613361336133613361336133613361336133610000000474726565000000013100000008" +
  "7a6f6e65413a6e31000000026e32";

/** locationProof = "zoneA", nonce = "n1:n2" — nửa còn lại. */
const VECTOR_FRAME_B =
  "50484f454e49584b45595f41535345545f4d494e543a0000005a6469643a70686f656e69783a6d6678377132776c336b356e703a3966396639663966396639663966396639663966396639663966396639663966396639663966396639663966396639663966396639663966396639663966396600000040336133613361336133613361336133613361336133613361336133613361336133613361336133613361336133613361336133613361336133613361336133610000000474726565000000013100000005" +
  "7a6f6e654100000005" +
  "6e313a6e32";

/** assetClass="farm", locationProof="Vườn Bưởi Đoan Hùng" (27 byte UTF-8, 19 ký tự). */
const VECTOR_UTF8 =
  "50484f454e49584b45595f41535345545f4d494e543a0000005a6469643a70686f656e69783a6d6678377132776c336b356e703a396639663966396639663966396639663966396639663966396639663966396639663966396639663966396639663966396639663966396639663966396639660000004033613361336133613361336133613361336133613361336133613361336133613361336133613361336133613361336133613361336133613361336133613361000000046661726d00000001310000001b" +
  "56c6b0e1bb9d6e2042c6b0e1bb9f6920c4906f616e2048c3b96e67000000026e31";

function hex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function input(over: Partial<Parameters<typeof buildAssetMintChallenge>[0]> = {}) {
  return {
    ownerDid: OWNER_DID,
    physicalIdHash: PHYSICAL_ID_HASH,
    assetClass: "tree",
    locationProof: "zoneA",
    nonce: "n1",
    ...over,
  };
}

// ─── Byte vectors ────────────────────────────────────────────────────────────

describe("buildAssetMintChallenge — vector byte tuyệt đối", () => {
  it("khớp từng byte với CanonicalMessage bên Java (trường hợp nền)", () => {
    expect(hex(buildAssetMintChallenge(input()))).toBe(VECTOR_BASE);
  });

  it("trả Uint8Array, không trả string", () => {
    expect(buildAssetMintChallenge(input())).toBeInstanceOf(Uint8Array);
  });

  it("mở đầu bằng prefix PHOENIXKEY_ASSET_MINT: dạng UTF-8 thô", () => {
    const bytes = buildAssetMintChallenge(input());
    const prefix = "PHOENIXKEY_ASSET_MINT:";
    expect(hex(bytes.slice(0, prefix.length))).toBe(
      hex(new TextEncoder().encode(prefix)),
    );
  });

  it("đóng khung độ dài 4 byte BIG-endian (không phải little-endian)", () => {
    // Field đầu là ownerDid, dài 0x5a = 90 byte → 00 00 00 5a, không phải 5a 00 00 00.
    const bytes = buildAssetMintChallenge(input());
    const at = "PHOENIXKEY_ASSET_MINT:".length;
    expect([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]).toEqual([0, 0, 0, 0x5a]);
  });

  it("đếm độ dài theo BYTE UTF-8, không theo ký tự", () => {
    // "Vườn Bưởi Đoan Hùng" = 19 ký tự nhưng 27 (0x1b) byte UTF-8.
    const bytes = buildAssetMintChallenge(
      input({ assetClass: "farm", locationProof: "Vườn Bưởi Đoan Hùng" }),
    );
    expect(hex(bytes)).toBe(VECTOR_UTF8);
    expect(hex(bytes)).toContain("0000001b");
  });
});

// ─── null ≠ "" ≠ "null" ──────────────────────────────────────────────────────

describe("buildAssetMintChallenge — locationProof vắng / rỗng / chuỗi \"null\"", () => {
  it("null → cờ vắng mặt \"0\" + giá trị rỗng", () => {
    expect(hex(buildAssetMintChallenge(input({ locationProof: null })))).toBe(
      VECTOR_LOCATION_NULL,
    );
  });

  it("undefined dựng ra đúng chuỗi như null (cùng là VẮNG)", () => {
    expect(hex(buildAssetMintChallenge(input({ locationProof: undefined })))).toBe(
      VECTOR_LOCATION_NULL,
    );
  });

  it("khoá vắng hẳn cũng là VẮNG", () => {
    const { locationProof: _omitted, ...withoutKey } = input();
    expect(hex(buildAssetMintChallenge(withoutKey))).toBe(VECTOR_LOCATION_NULL);
  });

  it("\"\" → cờ có mặt \"1\" + giá trị rỗng", () => {
    expect(hex(buildAssetMintChallenge(input({ locationProof: "" })))).toBe(
      VECTOR_LOCATION_EMPTY,
    );
  });

  it("\"null\" → cờ có mặt \"1\" + bốn byte 6e 75 6c 6c", () => {
    expect(hex(buildAssetMintChallenge(input({ locationProof: "null" })))).toBe(
      VECTOR_LOCATION_LITERAL_NULL,
    );
  });

  it("ba giá trị ra BA chuỗi thách thức khác nhau", () => {
    const distinct = new Set([
      VECTOR_LOCATION_NULL,
      VECTOR_LOCATION_EMPTY,
      VECTOR_LOCATION_LITERAL_NULL,
    ]);
    expect(distinct.size).toBe(3);
    expect(hex(buildAssetMintChallenge(input({ locationProof: null })))).not.toBe(
      hex(buildAssetMintChallenge(input({ locationProof: "" }))),
    );
    expect(hex(buildAssetMintChallenge(input({ locationProof: "" })))).not.toBe(
      hex(buildAssetMintChallenge(input({ locationProof: "null" }))),
    );
  });
});

// ─── Chống nhập nhằng khung ──────────────────────────────────────────────────

describe("buildAssetMintChallenge — chống nhập nhằng khung (lý do bỏ nối ':')", () => {
  it("locationProof=\"zoneA:n1\"+nonce=\"n2\" KHÁC locationProof=\"zoneA\"+nonce=\"n1:n2\"", () => {
    const a = hex(buildAssetMintChallenge(input({ locationProof: "zoneA:n1", nonce: "n2" })));
    const b = hex(buildAssetMintChallenge(input({ locationProof: "zoneA", nonce: "n1:n2" })));
    expect(a).toBe(VECTOR_FRAME_A);
    expect(b).toBe(VECTOR_FRAME_B);
    expect(a).not.toBe(b);
  });

  it("dời ranh giới giữa ownerDid và physicalIdHash cũng không đụng nhau", () => {
    // ownerDid tự nó chứa ':' — cách nối cũ cho hai bộ field khác nhau trùng byte.
    const a = hex(
      buildAssetMintChallenge({
        ownerDid: "did:phoenix:mfx7q2wl3k5np:" + "9f".repeat(32),
        physicalIdHash: PHYSICAL_ID_HASH,
        assetClass: "tree",
        locationProof: "zoneA",
        nonce: "n1",
      }),
    );
    const b = hex(
      buildAssetMintChallenge({
        ownerDid: "did:phoenix:mfx7q2wl3k5np",
        physicalIdHash: ":" + "9f".repeat(32) + PHYSICAL_ID_HASH.slice(1),
        assetClass: "tree",
        locationProof: "zoneA",
        nonce: "n1",
      }),
    );
    expect(a).not.toBe(b);
  });
});

// ─── Tập assetClass đóng ─────────────────────────────────────────────────────

describe("ASSET_CLASSES — tập đóng", () => {
  it("đúng 13 tên, ghim bằng literal", () => {
    expect([...ASSET_CLASSES]).toEqual([
      "farm",
      "plot",
      "tree",
      "animal",
      "fruit",
      "lot",
      "package",
      "land",
      "crop",
      "good",
      "container",
      "property",
      "commodity",
    ]);
  });

  it.each([...ASSET_CLASSES])("nhận \"%s\"", (cls) => {
    expect(isAllowedAssetClass(cls)).toBe(true);
    expect(() => buildAssetMintChallenge(input({ assetClass: cls }))).not.toThrow();
  });

  it.each([
    "organic",
    "organic_certified",
    "vietgap",
    "globalgap",
    "halal",
    "certified",
  ])("TỪ CHỐI \"%s\" — chứng nhận không phải assetClass", (cls) => {
    expect(isAllowedAssetClass(cls)).toBe(false);
    expect(() => buildAssetMintChallenge(input({ assetClass: cls }))).toThrow(
      /ngoài tập cho phép/,
    );
  });

  it("so khớp phân biệt hoa thường — \"Tree\" bị từ chối", () => {
    expect(isAllowedAssetClass("Tree")).toBe(false);
    expect(isAllowedAssetClass("FARM")).toBe(false);
  });

  it("từ chối chuỗi rỗng", () => {
    expect(isAllowedAssetClass("")).toBe(false);
  });
});

describe("buildAssetMintChallenge — trần locationProof", () => {
  it("chấp nhận đúng 120 ký tự", () => {
    expect(() =>
      buildAssetMintChallenge(input({ locationProof: "z".repeat(LOCATION_PROOF_MAX_LENGTH) })),
    ).not.toThrow();
  });

  it("từ chối 121 ký tự — backend @Size(max=120) sẽ 400", () => {
    expect(() =>
      buildAssetMintChallenge(
        input({ locationProof: "z".repeat(LOCATION_PROOF_MAX_LENGTH + 1) }),
      ),
    ).toThrow(/trần là 120/);
  });
});

// ─── createAsset (HTTP) ──────────────────────────────────────────────────────

function mockFetch(impl: (url: string, init: RequestInit) => Promise<Response>) {
  return jest.spyOn(globalThis, "fetch").mockImplementation(impl as typeof fetch);
}

function okResponse(result: unknown) {
  return new Response(JSON.stringify({ code: 1000, message: "Asset minted", result }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

function errorResponse(code: number, status: number, message = "boom") {
  return new Response(JSON.stringify({ code, message }), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

const REQUEST = {
  ownerDid: OWNER_DID,
  physicalIdHash: PHYSICAL_ID_HASH,
  assetClass: "tree",
  locationProof: "zoneA",
  nonce: "n1",
  ownerSignature: "deadbeef",
};

const MINTED = {
  asset_did: "did:phoenix:mfx7q2wl3k5np:" + "11".repeat(32),
  owner_did: OWNER_DID,
  tx_hash: "ab".repeat(32),
};

afterEach(() => {
  jest.restoreAllMocks();
});

describe("AssetModule.createAsset — đường dây", () => {
  it("POST đúng /identity/asset/create trên base URL đã cấu hình", async () => {
    let seenUrl = "";
    let seenMethod = "";
    mockFetch(async (url, init) => {
      seenUrl = url;
      seenMethod = String(init.method);
      return okResponse(MINTED);
    });

    const asset = new AssetModule(BASE, () => "jwt-abc");
    await expect(asset.createAsset(REQUEST)).resolves.toEqual(MINTED);
    expect(seenUrl).toBe(`${BASE}/identity/asset/create`);
    expect(seenMethod).toBe("POST");
  });

  it("gắn Authorization: Bearer khi có session token", async () => {
    let seenAuth: string | undefined;
    mockFetch(async (_url, init) => {
      seenAuth = (init.headers as Record<string, string>).Authorization;
      return okResponse(MINTED);
    });

    const asset = new AssetModule(BASE, () => "jwt-abc");
    await asset.createAsset(REQUEST);
    expect(seenAuth).toBe("Bearer jwt-abc");
  });

  it("thiếu session token ⇒ ném TẠI CLIENT, không chạm mạng", async () => {
    // `/identity/asset/create` không nằm trong danh sách miễn trừ nào của
    // `AuthRequiredInterceptor` (mặc-định-từ-chối) ⇒ thiếu Bearer là 401 chắc
    // chắn. Gửi đi để nhận 401 không nói thêm được gì mà người gọi chưa biết.
    const spy = mockFetch(async () => okResponse(MINTED));

    const asset = new AssetModule(BASE, () => null);
    await expect(asset.createAsset(REQUEST)).rejects.toThrow(
      "No session token — user must login first",
    );
    expect(spy).not.toHaveBeenCalled();
  });

  it("ownerSignature KHÔNG thay được Bearer — hai lớp khác nhau", async () => {
    // Chữ ký owner chứng minh CHỦ SỞ HỮU ĐỒNG Ý; Bearer chứng minh PHIÊN GỌI
    // HỢP LỆ. Có chữ ký đầy đủ mà không có phiên thì vẫn phải dừng.
    const spy = mockFetch(async () => okResponse(MINTED));

    const asset = new AssetModule(BASE, () => null);
    await expect(
      asset.createAsset({ ...REQUEST, ownerSignature: "ff".repeat(64) }),
    ).rejects.toThrow(/No session token/);
    expect(spy).not.toHaveBeenCalled();
  });

  it("cổng phiên chặn TRƯỚC cả khâu kiểm assetClass", async () => {
    // Thiếu phiên thì không được đi tiếp, bất kể tải trọng đúng hay sai.
    const asset = new AssetModule(BASE, () => null);
    await expect(
      asset.createAsset({ ...REQUEST, assetClass: "organic" }),
    ).rejects.toThrow(/No session token/);
  });

  it("thân request đổi sang snake_case đúng tên DTO Java", async () => {
    let body: Record<string, unknown> = {};
    mockFetch(async (_url, init) => {
      body = JSON.parse(String(init.body));
      return okResponse(MINTED);
    });

    const asset = new AssetModule(BASE, () => "jwt-abc");
    await asset.createAsset(REQUEST);
    expect(body).toEqual({
      owner_did: OWNER_DID,
      asset_class: "tree",
      physical_id_hash: PHYSICAL_ID_HASH,
      location_proof: "zoneA",
      owner_signature: "deadbeef",
      nonce: "n1",
    });
  });

  it("locationProof vắng ⇒ bỏ hẳn khoá; \"\" ⇒ vẫn lên dây", async () => {
    const bodies: Record<string, unknown>[] = [];
    mockFetch(async (_url, init) => {
      bodies.push(JSON.parse(String(init.body)));
      return okResponse(MINTED);
    });

    const asset = new AssetModule(BASE, () => "jwt-abc");
    await asset.createAsset({ ...REQUEST, locationProof: null });
    await asset.createAsset({ ...REQUEST, locationProof: "" });

    expect("location_proof" in bodies[0]).toBe(false);
    expect(bodies[1].location_proof).toBe("");
  });

  it("chặn assetClass ngoài tập TRƯỚC khi chạm mạng", async () => {
    const spy = mockFetch(async () => okResponse(MINTED));
    const asset = new AssetModule(BASE, () => "jwt-abc");
    await expect(
      asset.createAsset({ ...REQUEST, assetClass: "organic" }),
    ).rejects.toThrow(/ngoài tập cho phép/);
    expect(spy).not.toHaveBeenCalled();
  });
});

describe("AssetModule.createAsset — map lỗi", () => {
  it.each([
    [1340, 404, "owner_did_not_found"],
    [1341, 403, "owner_signature_invalid"],
    [1342, 409, "physical_id_already_claimed"],
    [1346, 400, "owner_cannot_own_asset"],
    [1353, 400, "asset_class_not_allowed"],
    [1354, 404, "owner_key_not_found"],
  ])("mã thô %i → code \"%s\"", async (raw, status, expected) => {
    mockFetch(async () => errorResponse(raw as number, status as number));
    const asset = new AssetModule(BASE, () => "jwt-abc");
    await expect(asset.createAsset(REQUEST)).rejects.toMatchObject({
      code: expected,
      rawCode: raw,
      status,
    });
    await expect(asset.createAsset(REQUEST)).rejects.toBeInstanceOf(PhoenixKeyError);
  });

  it.each([
    [1351, "vault_not_found bên activation"],
    [1352, "pot_unavailable bên activation"],
  ])("KHÔNG nhận %i làm mã asset nữa — đã nhường cho %s", async (raw) => {
    mockFetch(async () => errorResponse(raw as number, 404));
    const asset = new AssetModule(BASE, () => "jwt-abc");
    await expect(asset.createAsset(REQUEST)).rejects.toMatchObject({
      code: "http_404",
      rawCode: raw,
    });
  });

  it("ghim bảng ASSET_ERROR_CODES bằng literal", () => {
    expect(ASSET_ERROR_CODES).toEqual({
      1340: "owner_did_not_found",
      1341: "owner_signature_invalid",
      1342: "physical_id_already_claimed",
      1346: "owner_cannot_own_asset",
      1353: "asset_class_not_allowed",
      1354: "owner_key_not_found",
    });
  });

  it("không ghi đè mã đã có tên từ bảng toàn cục (3006 nonce_already_used)", async () => {
    mockFetch(async () => errorResponse(3006, 409));
    const asset = new AssetModule(BASE, () => "jwt-abc");
    await expect(asset.createAsset(REQUEST)).rejects.toMatchObject({
      code: "nonce_already_used",
    });
  });

  it("lỗi mạng vẫn là network_error, không bị nhuộm thành lỗi asset", async () => {
    mockFetch(async () => {
      throw new TypeError("connection refused");
    });
    const asset = new AssetModule(BASE, () => "jwt-abc");
    await expect(asset.createAsset(REQUEST)).rejects.toMatchObject({
      code: "network_error",
      status: 0,
    });
  });

  it("mã lạ giữ nguyên mã chung của fetcher — không đoán bừa", async () => {
    // Non-2xx chưa có tên: fetcher đặt `http_<status>`. Bảng asset không nhận
    // 1399 nên không được phép bịa ra một cái tên cho nó.
    mockFetch(async () => errorResponse(1399, 400));
    const asset = new AssetModule(BASE, () => "jwt-abc");
    await expect(asset.createAsset(REQUEST)).rejects.toMatchObject({
      code: "http_400",
      rawCode: 1399,
    });
  });
});
