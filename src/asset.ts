/**
 * PhoenixKey SDK — Asset Module
 *
 * Đúc AssetDID cho một tài sản vật lý (nông trại, lô, cây, con, quả, kiện hàng)
 * do một PersonDID / OrgDID / ServiceDID sở hữu.
 * Backend endpoint: POST /identity/asset/create.
 *
 * Hợp đồng canonical ở đây chép từ mã Java thật, KHÔNG suy đoán:
 * - `PhoenixKey-Database/.../service/identity/AssetCanonical.java`
 * - `PhoenixKey-Database/.../common/CanonicalMessage.java`
 * - `PhoenixKey-Database/.../dto/identity/AssetCreate{Request,Response}.java`
 * - `PhoenixKey-Database/.../controller/IdentityController.java`
 */

import { createFetcher, FetchOptions } from "./fetcher";
import { PhoenixKeyError } from "./types";

// ─── Canonical challenge ──────────────────────────────────────────────────────

/** Domain prefix của luồng đúc AssetDID (`AssetCanonical.ASSET_MINT_PREFIX`). */
export const ASSET_MINT_PREFIX = "PHOENIXKEY_ASSET_MINT:";

/** Cờ `locationProof` vắng mặt — `null`/`undefined` (`AssetCanonical.LOCATION_ABSENT`). */
export const LOCATION_ABSENT = "0";

/** Cờ `locationProof` có mặt — kể cả chuỗi rỗng (`AssetCanonical.LOCATION_PRESENT`). */
export const LOCATION_PRESENT = "1";

/** Trần độ dài `locationProof` — `@Size(max = 120)` bên DTO Java. */
export const LOCATION_PROOF_MAX_LENGTH = 120;

/**
 * Tập `assetClass` ĐÓNG — chép nguyên từ
 * `AssetCanonical.ALLOWED_ASSET_CLASSES`. Ngoài tập ⇒ backend từ chối 400
 * `asset_class_not_allowed` (mã thô 1351).
 *
 * Sáu tên đầu là phân loại OriLifeTrace; bảy tên sau khớp `asset_class` ở
 * `PhoenixKey-Specs/PhoenixKey-Math.md` §17, viết thường.
 *
 * ⚠ **CHỨNG NHẬN KHÔNG PHẢI `assetClass`.** Trường này nằm TRONG phần chủ sở
 * hữu ký, nên mọi giá trị lọt vào đây là lời chủ sở hữu **tự khai về chính
 * mình**. `organic`, `vietgap`, `globalgap`, `halal`… là **chứng thực của bên
 * thứ ba** — tổ chức chứng nhận ký, có hiệu lực, thu hồi được — và phải đi bằng
 * Verifiable Credential trỏ tới AssetDID, không phải bằng trường phân loại này.
 * Ai mở tập này ra cho một giá trị mang nghĩa "đã được chứng nhận" là biến lời
 * tự khai thành lời chứng thực trước mắt siêu thị và người mua. Đừng mở.
 */
export const ASSET_CLASSES = [
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
] as const;

/** Một giá trị thuộc {@link ASSET_CLASSES}. */
export type AssetClass = (typeof ASSET_CLASSES)[number];

/**
 * `true` nếu `assetClass` nằm trong tập đóng. So khớp phân biệt hoa thường —
 * backend dùng `Set.contains`, `"Tree"` KHÔNG hợp lệ.
 */
export function isAllowedAssetClass(assetClass: string): assetClass is AssetClass {
  return (ASSET_CLASSES as readonly string[]).includes(assetClass);
}

/** Đầu vào dựng chuỗi thách thức đúc AssetDID. */
export type AssetMintChallengeInput = {
  /** DID sẽ sở hữu AssetDID — Person, Org hoặc Service. Asset không làm cha được. */
  ownerDid: string;
  /** SHA-256 đặc trưng vật lý ổn định — 64 ký tự hex thường. */
  physicalIdHash: string;
  /** Phân loại — phải thuộc {@link ASSET_CLASSES}. */
  assetClass: string;
  /**
   * Băm vùng GPS thô, tuỳ chọn. `null`/`undefined` (vắng), `""` và `"null"` là
   * BA giá trị khác nhau và sinh ba chuỗi thách thức khác nhau.
   */
  locationProof?: string | null;
  /** Nonce chống phát lại — server tiêu thụ một lần cho mỗi `(ownerDid, nonce)`. */
  nonce: string;
};

const encoder = new TextEncoder();

/**
 * Nối `domainPrefix` với các field, mỗi field đóng khung bằng **4 byte độ dài
 * big-endian** — bản TypeScript của `CanonicalMessage.build`.
 */
function canonicalMessage(domainPrefix: string, fields: string[]): Uint8Array {
  const prefix = encoder.encode(domainPrefix);
  const encoded = fields.map((f) => encoder.encode(f));

  let total = prefix.length;
  for (const f of encoded) total += 4 + f.length;

  const out = new Uint8Array(total);
  out.set(prefix, 0);
  let at = prefix.length;
  for (const f of encoded) {
    const len = f.length;
    out[at] = (len >>> 24) & 0xff;
    out[at + 1] = (len >>> 16) & 0xff;
    out[at + 2] = (len >>> 8) & 0xff;
    out[at + 3] = len & 0xff;
    at += 4;
    out.set(f, at);
    at += len;
  }
  return out;
}

/**
 * Dựng chuỗi **byte** mà owner phải ký để đúc AssetDID.
 *
 * Thứ tự field cố định: `ownerDid`, `physicalIdHash`, `assetClass`,
 * cờ-hiện-diện-`locationProof`, `locationProof`, `nonce` — mỗi field đóng khung
 * bằng 4 byte độ dài big-endian, đặt sau prefix {@link ASSET_MINT_PREFIX}.
 *
 * Trả `Uint8Array` chứ không phải string: đóng khung theo độ dài là chuyện
 * **byte** (độ dài đếm byte UTF-8, không đếm ký tự), và khoá ký nhận byte.
 *
 * ⚠ **Phá tương thích ngược.** Công thức cũ nối bằng `':'`
 * (`prefix + ownerDid + ":" + physicalIdHash + ":" + assetClass + ":" + nonce`)
 * và bỏ qua `locationProof` — client nào còn ký kiểu đó nhận
 * `owner_signature_invalid`. Hai lý do đổi:
 * - `locationProof` **vào trong** phần được ký: đó là vùng trồng, thứ cả bài
 *   toán truy xuất nguồn gốc bán ra. Trước đây nó nằm ngoài chữ ký nhưng vẫn
 *   được lưu, nên mọi trung gian đổi được sang vùng cao giá mà chữ ký owner vẫn
 *   hợp lệ.
 * - Đóng khung độ dài thay cho nối `':'`: `ownerDid` tự nó chứa `':'` và
 *   `locationProof` là chuỗi tự do, nên nối bằng dấu phân tách cho hai bộ field
 *   KHÁC NHAU sinh cùng một chuỗi byte (dời ranh giới field).
 *
 * @throws Error nếu `assetClass` ngoài tập đóng, hoặc `locationProof` dài quá
 *   {@link LOCATION_PROOF_MAX_LENGTH} — hai trường hợp backend chắc chắn từ
 *   chối, ký ra rồi mới biết là phí một vòng ký của người dùng.
 */
export function buildAssetMintChallenge(input: AssetMintChallengeInput): Uint8Array {
  if (!isAllowedAssetClass(input.assetClass)) {
    throw new Error(
      `assetClass "${input.assetClass}" ngoài tập cho phép — ` +
        `chọn một trong: ${[...ASSET_CLASSES].sort().join(", ")}. ` +
        `Chứng nhận (organic/VietGAP/GlobalGAP) không phải assetClass; ` +
        `nó là Verifiable Credential trỏ tới AssetDID.`,
    );
  }

  const lp = input.locationProof;
  // `@Size(max=120)` bên Java đếm ký tự UTF-16, `String.length` ở JS cũng vậy —
  // hai bên đếm cùng đơn vị, không lệch ở ký tự tiếng Việt hay emoji.
  if (lp != null && lp.length > LOCATION_PROOF_MAX_LENGTH) {
    throw new Error(
      `locationProof dài ${lp.length} ký tự, trần là ${LOCATION_PROOF_MAX_LENGTH}`,
    );
  }

  // `undefined` và `null` đều là VẮNG; `""` là CÓ MẶT với giá trị rỗng.
  const absent = lp == null;
  return canonicalMessage(ASSET_MINT_PREFIX, [
    input.ownerDid,
    input.physicalIdHash,
    input.assetClass,
    absent ? LOCATION_ABSENT : LOCATION_PRESENT,
    absent ? "" : lp,
    input.nonce,
  ]);
}

// ─── Request / response ───────────────────────────────────────────────────────

/**
 * Thân request `POST /identity/asset/create`.
 *
 * Tên trường trên dây là snake_case (Jackson `property-naming-strategy:
 * SNAKE_CASE` toàn cục, DTO asset không override) — module này lo việc đổi tên,
 * người gọi viết camelCase như mọi chỗ khác trong SDK.
 */
export type AssetCreateRequest = AssetMintChallengeInput & {
  /**
   * Chữ ký hex của owner trên {@link buildAssetMintChallenge} — bằng khoá
   * **vai OWNER** đang active của `ownerDid`. Khoá vai khác bị từ chối.
   */
  ownerSignature: string;
};

/** Kết quả `POST /identity/asset/create`. */
export type AssetCreateResponse = {
  /** AssetDID vừa đúc. */
  asset_did: string;
  /** Vọng lại `ownerDid` để người gọi xác nhận ràng buộc. */
  owner_did: string;
  /**
   * Tx hash publish metadata-6789 (đường quá độ); sẽ đổi sang tx hash đúc TAAD
   * UTxO khi validator on-chain lên.
   */
  tx_hash: string;
};

/**
 * Mã lỗi thô → mã chuỗi, **chỉ trong phạm vi `/identity/asset/create`**.
 *
 * Cố ý KHÔNG nhập vào `ERROR_CODE_MAP` toàn cục ở `fetcher.ts`: bên backend
 * `ErrorCode.java` dùng lại số 1351 và 1352 cho hai nghĩa khác nhau —
 * `ASSET_CLASS_NOT_ALLOWED`/`OWNER_KEY_NOT_FOUND` ở luồng asset, nhưng
 * `VAULT_NOT_FOUND`/`POT_UNAVAILABLE` ở luồng activation. Một bảng toàn cục
 * khoá theo số nguyên sẽ dịch sai một trong hai luồng, nên bảng này gắn với
 * đúng endpoint sinh ra nó.
 */
export const ASSET_ERROR_CODES: Record<number, string> = {
  1340: "owner_did_not_found",
  1341: "owner_signature_invalid",
  1342: "physical_id_already_claimed",
  1346: "owner_cannot_own_asset",
  1351: "asset_class_not_allowed",
  1352: "owner_key_not_found",
};

/**
 * Làm mịn mã lỗi của một `PhoenixKeyError` theo bảng {@link ASSET_ERROR_CODES}.
 * Chỉ đụng vào lỗi mà fetcher chưa dịch được (`code_<n>` / `http_<n>`) — lỗi đã
 * có tên từ bảng toàn cục thì giữ nguyên.
 */
function refineAssetError(err: unknown): unknown {
  if (!(err instanceof PhoenixKeyError)) return err;
  if (err.rawCode === undefined) return err;
  const refined = ASSET_ERROR_CODES[err.rawCode];
  if (!refined) return err;
  if (!/^(code_|http_)/.test(err.code)) return err;

  return new PhoenixKeyError({
    status: err.status,
    rawCode: err.rawCode,
    code: refined,
    message: err.message,
    userMessageKey: err.userMessageKey,
    details: err.details,
  });
}

// ─── Module ───────────────────────────────────────────────────────────────────

export class AssetModule {
  private readonly fetch: ReturnType<typeof createFetcher>;

  constructor(
    private readonly baseUrl: string,
    private readonly _getSessionToken: () => string | null,
  ) {
    this.fetch = createFetcher(baseUrl);
  }

  /**
   * Đúc AssetDID cho một tài sản vật lý — `POST /identity/asset/create`.
   *
   * Quyền đúc do **`ownerSignature`** quyết định, không do session: server kiểm
   * chữ ký bằng khoá vai OWNER đang active của `ownerDid`. Session token, nếu
   * có trong localStorage, vẫn được gắn kèm `Authorization: Bearer` để endpoint
   * ghi được nhật ký theo phiên và để còn dùng được nếu backend siết cổng sau
   * này — nhưng **không bắt buộc**: gọi khi chưa đăng nhập vẫn đi tiếp, vì cổng
   * thật nằm ở chữ ký.
   *
   * First-claim-wins: mỗi `physicalIdHash` chỉ claim được một lần. Hai request
   * đồng thời cho cùng một quả ra đúng một 200 và một
   * `physical_id_already_claimed` (409) — ràng buộc UNIQUE dưới DB quyết định,
   * không có khe hở đua.
   *
   * @throws PhoenixKeyError với `code` trong {@link ASSET_ERROR_CODES}, hoặc mã
   *   chung của fetcher (`timeout`, `network_error`, `http_<status>`).
   */
  async createAsset(request: AssetCreateRequest): Promise<AssetCreateResponse> {
    // Dựng thách thức để kiểm đầu vào ngay tại chỗ gọi: `assetClass` ngoài tập
    // và `locationProof` quá dài ném lỗi ở đây thay vì đi một vòng mạng.
    buildAssetMintChallenge(request);

    const body: Record<string, string> = {
      owner_did: request.ownerDid,
      asset_class: request.assetClass,
      physical_id_hash: request.physicalIdHash,
      owner_signature: request.ownerSignature,
      nonce: request.nonce,
    };
    // `""` là giá trị CÓ MẶT và phải lên dây; vắng mặt thì bỏ hẳn khoá — Jackson
    // đọc khoá thiếu thành `null`, đúng nhánh cờ "0" của challenge.
    if (request.locationProof != null) {
      body.location_proof = request.locationProof;
    }

    const token = this._getSessionToken();
    try {
      return await this.fetch<AssetCreateResponse>("/identity/asset/create", {
        method: "POST",
        body: JSON.stringify(body),
        ...(token ? { bearerToken: token } : {}),
      } as FetchOptions);
    } catch (err) {
      throw refineAssetError(err);
    }
  }
}
