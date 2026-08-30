import {
  ASSET_CLASSES,
  ASSET_ERROR_CODES,
  AssetModule,
  buildAssetMintChallenge,
  computeAssetCommitment,
  isAllowedAssetClass,
  LOCATION_PROOF_MAX_LENGTH,
  verifyAssetCommitment,
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

// ─── computeAssetCommitment / verifyAssetCommitment — vector tuyệt đối ───────
// Mọi hex dưới đây LITERAL, sinh bằng cách hiện thực lại
// CanonicalMessage.build (prefix PHOENIXKEY_ASSET_COMMIT: + field đóng khung
// 4-byte-độ-dài-big-endian, KHÔNG có ownerDid/nonce) + sha256 bằng python3,
// đúng công thức AssetCanonical.commitment(salt, physicalIdHash, assetClass,
// locationProof). KHÔNG do computeAssetCommitment tự tính ra.

/** Muối 1 — 64 ký tự hex, dùng cho phần lớn vector dưới đây. */
const SALT_1 = "c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1";
/** Muối 2 — khác SALT_1, dùng để chứng minh cùng dữ liệu + muối khác ⇒ cam kết khác. */
const SALT_2 = "d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2";
/** physicalIdHash SAI — lệch 1 ký tự so với PHYSICAL_ID_HASH ("3a" → "3b"). */
const WRONG_PHYSICAL_ID_HASH = "3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b";

/** salt=SALT_1, physicalIdHash=PHYSICAL_ID_HASH, assetClass="tree", locationProof="zoneA". */
const COMMIT_BASE = "262839c11806df194d290eb58b754370ac528d6370d0c7154fde78a32c85967c";
/** Như trên nhưng salt=SALT_2 — cùng dữ liệu, muối khác ⇒ cam kết khác. */
const COMMIT_SALT2 = "0ec76b77339c9890962c2483d78b4b0f5c72e8594c81d0629f56998157efd3a2";
/** Như COMMIT_BASE nhưng physicalIdHash sai. */
const COMMIT_WRONG_PHYS = "6d19700dd61d89e99b88c98c44dd429c05994febff446dbc30c6c96338830741";
/** Như COMMIT_BASE nhưng assetClass="farm" thay vì "tree". */
const COMMIT_WRONG_CLASS = "7314f2695010828cb59dfec1142bdea1bd3bf61c99e27abf49fa84a03dabdc2f";
/** Như COMMIT_BASE nhưng locationProof="zoneB" thay vì "zoneA". */
const COMMIT_WRONG_LOC = "3982ee6d85d77eef4dd142d86b17892562b5ab523c7ce23579c16e3dbb66e333";
/** Như COMMIT_BASE nhưng locationProof vắng mặt (null) — cờ "0", giá trị rỗng. */
const COMMIT_LOCATION_NULL = "0ec7a5a31918777261978d3d09ddb8518e0c2149159f52654bb599a5781f3533";

function commitInput(over: Partial<Parameters<typeof computeAssetCommitment>[0]> = {}) {
  return {
    salt: SALT_1,
    physicalIdHash: PHYSICAL_ID_HASH,
    assetClass: "tree",
    locationProof: "zoneA",
    ...over,
  };
}

describe("computeAssetCommitment — vector tuyệt đối", () => {
  it("khớp cam kết Java (trường hợp nền: salt1, tree, zoneA)", () => {
    expect(computeAssetCommitment(commitInput())).toBe(COMMIT_BASE);
  });

  it("trả hex thường 64 ký tự", () => {
    const c = computeAssetCommitment(commitInput());
    expect(c).toMatch(/^[0-9a-f]{64}$/);
  });

  it("locationProof vắng (null) khớp vector riêng", () => {
    expect(computeAssetCommitment(commitInput({ locationProof: null }))).toBe(
      COMMIT_LOCATION_NULL,
    );
  });
});

describe("verifyAssetCommitment — kỷ luật muối (≥4 test bắt buộc)", () => {
  // (a) cùng dữ liệu + muối khác ⇒ cam kết khác
  it("(a) cùng dữ liệu, muối khác nhau ⇒ cam kết khác nhau", () => {
    const c1 = computeAssetCommitment(commitInput({ salt: SALT_1 }));
    const c2 = computeAssetCommitment(commitInput({ salt: SALT_2 }));
    expect(c1).toBe(COMMIT_BASE);
    expect(c2).toBe(COMMIT_SALT2);
    expect(c1).not.toBe(c2);
  });

  // (b) muối đúng + dữ liệu đúng ⇒ khớp
  it("(b) muối đúng + dữ liệu đúng ⇒ verifyAssetCommitment trả true", () => {
    expect(
      verifyAssetCommitment({ ...commitInput(), commitment: COMMIT_BASE }),
    ).toBe(true);
  });

  it("(b) so khớp KHÔNG phân biệt hoa/thường của commitment truyền vào", () => {
    expect(
      verifyAssetCommitment({
        ...commitInput(),
        commitment: COMMIT_BASE.toUpperCase(),
      }),
    ).toBe(true);
  });

  // (c) sai BẤT KỲ một trường ⇒ lệch
  it.each([
    ["salt", { salt: SALT_2 }],
    ["physicalIdHash", { physicalIdHash: WRONG_PHYSICAL_ID_HASH }],
    ["assetClass", { assetClass: "farm" }],
    ["locationProof", { locationProof: "zoneB" }],
  ])("(c) sai trường %s ⇒ verifyAssetCommitment trả false", (_label, over) => {
    expect(
      verifyAssetCommitment({ ...commitInput(), ...over, commitment: COMMIT_BASE }),
    ).toBe(false);
  });

  it("(c) commitment on-chain bị sửa 1 ký tự ⇒ trả false", () => {
    const tampered = "0" + COMMIT_BASE.slice(1);
    expect(verifyAssetCommitment({ ...commitInput(), commitment: tampered })).toBe(false);
  });

  // (d) muối rỗng/thiếu ⇒ KHÔNG được im lặng trả true
  it('(d) salt="" ⇒ ném lỗi, KHÔNG trả true', () => {
    expect(() =>
      verifyAssetCommitment({ ...commitInput(), salt: "", commitment: COMMIT_BASE }),
    ).toThrow(/salt phải là chuỗi hex/);
  });

  it("(d) salt thiếu hẳn (undefined) ⇒ ném lỗi, KHÔNG trả true", () => {
    const { salt: _omitted, ...withoutSalt } = commitInput();
    expect(() =>
      verifyAssetCommitment({ ...withoutSalt, commitment: COMMIT_BASE } as never),
    ).toThrow(/salt phải là chuỗi hex/);
  });

  it("(d) salt sai độ dài (63 ký tự thay vì 64) ⇒ ném lỗi, KHÔNG trả true", () => {
    expect(() =>
      verifyAssetCommitment({
        ...commitInput(),
        salt: SALT_1.slice(0, 63),
        commitment: COMMIT_BASE,
      }),
    ).toThrow(/salt phải là chuỗi hex/);
  });

  it("(d) computeAssetCommitment cũng ném lỗi cho salt thiếu — không có preimage giả", () => {
    expect(() => computeAssetCommitment(commitInput({ salt: undefined as never }))).toThrow(
      /salt phải là chuỗi hex/,
    );
  });

  it("commitment rỗng ⇒ ném lỗi thay vì so sánh mù", () => {
    expect(() =>
      verifyAssetCommitment({ ...commitInput(), commitment: "" }),
    ).toThrow(/commitment rỗng\/thiếu/);
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
    [1380, 400, "asset_class_not_allowed"],
    [1381, 404, "owner_key_not_found"],
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

  it.each([1353, 1354, 1355])(
    "KHÔNG nhận %i — số đã NGHỈ HƯU (Wakeme v5 #67), giữ trống có chủ ý",
    async (raw) => {
      // 1353-1355 từng là NOT_IN_PHASE2/CLAIM_AMOUNT_EXCEEDS_VESTED/ALREADY_IN_PHASE2,
      // đã bỏ. Client cũ nào còn cầm số này không được SDK dịch hộ thành tên asset —
      // đó là gọi tên sai đúng lớp lỗi vừa vá.
      mockFetch(async () => errorResponse(raw, 400));
      const asset = new AssetModule(BASE, () => "jwt-abc");
      await expect(asset.createAsset(REQUEST)).rejects.toMatchObject({
        code: "http_400",
        rawCode: raw,
      });
    },
  );

  it("ghim bảng ASSET_ERROR_CODES bằng literal", () => {
    expect(ASSET_ERROR_CODES).toEqual({
      1340: "owner_did_not_found",
      1341: "owner_signature_invalid",
      1342: "physical_id_already_claimed",
      1346: "owner_cannot_own_asset",
      1380: "asset_class_not_allowed",
      1381: "owner_key_not_found",
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

// ─── AssetModule.checkCommitment ──────────────────────────────────────────────

const ASSET_DID = "did:phoenix:mfx7q2wl3k5np:" + "11".repeat(32);

const COMMITMENT_CHECK_MATCH = {
  did: ASSET_DID,
  status: "MATCH",
  on_chain_commitment: COMMIT_BASE,
  recomputed_commitment: COMMIT_BASE,
  commitment_salt: SALT_1,
  asset_class: "tree",
  genesis_tx_hash: "ab".repeat(32),
};

describe("AssetModule.checkCommitment — đường dây", () => {
  it("GET đúng /identity/{did}/commitment-check trên base URL đã cấu hình", async () => {
    let seenUrl = "";
    let seenMethod = "";
    mockFetch(async (url, init) => {
      seenUrl = url;
      seenMethod = String(init.method);
      return okResponse(COMMITMENT_CHECK_MATCH);
    });

    const asset = new AssetModule(BASE, () => "jwt-abc");
    await expect(asset.checkCommitment(ASSET_DID)).resolves.toEqual(COMMITMENT_CHECK_MATCH);
    expect(seenUrl).toBe(`${BASE}/identity/${encodeURIComponent(ASSET_DID)}/commitment-check`);
    expect(seenMethod).toBe("GET");
  });

  it("gắn Authorization: Bearer khi có session token", async () => {
    let seenAuth: string | undefined;
    mockFetch(async (_url, init) => {
      seenAuth = (init.headers as Record<string, string>).Authorization;
      return okResponse(COMMITMENT_CHECK_MATCH);
    });

    const asset = new AssetModule(BASE, () => "jwt-abc");
    await asset.checkCommitment(ASSET_DID);
    expect(seenAuth).toBe("Bearer jwt-abc");
  });

  it("thiếu session token ⇒ ném TẠI CLIENT, KHÔNG chạm mạng", async () => {
    // Endpoint đòi Bearer (không nằm trong PUBLIC_GET của AuthRequiredInterceptor) —
    // gửi đi để nhận 401 không nói thêm được gì mà người gọi đã biết trước.
    const spy = mockFetch(async () => okResponse(COMMITMENT_CHECK_MATCH));

    const asset = new AssetModule(BASE, () => null);
    await expect(asset.checkCommitment(ASSET_DID)).rejects.toThrow(
      "No session token — user must login first",
    );
    expect(spy).not.toHaveBeenCalled();
  });

  it.each(["MATCH", "MISMATCH", "NO_COMMITMENT_LEGACY", "NO_SALT_UNVERIFIABLE", "NOT_ANCHORED", "NOT_AN_ASSET"])(
    "map đủ trạng thái \"%s\" không gộp/đổi tên",
    async (status) => {
      const payload = { ...COMMITMENT_CHECK_MATCH, status };
      mockFetch(async () => okResponse(payload));
      const asset = new AssetModule(BASE, () => "jwt-abc");
      const result = await asset.checkCommitment(ASSET_DID);
      expect(result.status).toBe(status);
    },
  );

  it("lỗi mạng vẫn là network_error", async () => {
    mockFetch(async () => {
      throw new TypeError("connection refused");
    });
    const asset = new AssetModule(BASE, () => "jwt-abc");
    await expect(asset.checkCommitment(ASSET_DID)).rejects.toMatchObject({
      code: "network_error",
      status: 0,
    });
  });

  it("DID lạ ⇒ dùng mã lỗi TOÀN CỤC (user_did_not_found = 2002), không qua ASSET_ERROR_CODES", async () => {
    mockFetch(async () => errorResponse(2002, 404));
    const asset = new AssetModule(BASE, () => "jwt-abc");
    await expect(asset.checkCommitment(ASSET_DID)).rejects.toMatchObject({
      code: "user_did_not_found",
      rawCode: 2002,
    });
  });
});
