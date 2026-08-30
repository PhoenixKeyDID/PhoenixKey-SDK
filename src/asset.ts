/**
 * PhoenixKey SDK — Asset Module
 *
 * Đúc AssetDID cho một tài sản vật lý (nông trại, lô, cây, con, quả, kiện hàng)
 * do một PersonDID / OrgDID / ServiceDID sở hữu.
 * Backend endpoint: POST /identity/asset/create.
 *
 * Cũng cấp phần đối chiếu cam kết on-chain (`GET /identity/{did}/commitment-check`)
 * và hàm kiểm cam kết thuần client `verifyAssetCommitment`.
 *
 * Hợp đồng canonical ở đây chép từ mã Java thật, KHÔNG suy đoán:
 * - `PhoenixKey-Database/.../service/identity/AssetCanonical.java`
 * - `PhoenixKey-Database/.../common/CanonicalMessage.java`
 * - `PhoenixKey-Database/.../dto/identity/AssetCreate{Request,Response}.java`
 * - `PhoenixKey-Database/.../dto/identity/CommitmentCheck{Status,Response}.java`
 * - `PhoenixKey-Database/.../controller/IdentityController.java`
 * - `PhoenixKey-Database/.../exception/ErrorCode.java`
 */

import { sha256 } from "@noble/hashes/sha256";
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
 * `asset_class_not_allowed` (mã thô 1380).
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

// ─── Cam kết on-chain ─────────────────────────────────────────────────────────

/**
 * Domain prefix riêng cho cam kết on-chain (`AssetCanonical.ASSET_COMMIT_PREFIX`).
 * KHÁC {@link ASSET_MINT_PREFIX} — cố ý, để chữ ký challenge không tái dùng
 * chéo được sang tiền-ảnh cam kết.
 */
export const ASSET_COMMIT_PREFIX = "PHOENIXKEY_ASSET_COMMIT:";

/** Độ dài muối cam kết tính bằng byte (`AssetCanonical.SALT_BYTES`). */
export const COMMITMENT_SALT_BYTES = 32;

/** Độ dài muối khi mã hex thường (`AssetCanonical.SALT_HEX_LENGTH`). */
export const COMMITMENT_SALT_HEX_LENGTH = COMMITMENT_SALT_BYTES * 2;

/** Đầu vào tính/kiểm cam kết on-chain của một AssetDID. */
export type VerifyAssetCommitmentInput = {
  /**
   * Muối 32 byte, hex thường, đúng 64 ký tự — MỘT muối riêng cho MỖI bản ghi
   * (`asset_dids.commitment_salt`, hoặc trường `commitment_salt` trả về từ
   * {@link AssetModule.checkCommitment}). Muối đi vào tiền-ảnh dưới dạng
   * chính CHUỖI HEX của nó (như `physicalIdHash`), KHÔNG decode ngược thành
   * 32 byte thô trước — `AssetCanonical.commitment` truyền thẳng `String salt`
   * cho `CanonicalMessage.build`, hàm đó tự UTF-8 hoá field string.
   */
  salt: string;
  /** SHA-256 đặc trưng vật lý — phải khớp giá trị đã dùng lúc đúc. */
  physicalIdHash: string;
  /** Phân loại — phải khớp giá trị đã dùng lúc đúc. */
  assetClass: string;
  /**
   * Băm vùng GPS — phải khớp giá trị đã dùng lúc đúc. Cùng quy ước vắng/rỗng
   * như {@link AssetMintChallengeInput.locationProof}: `null`/`undefined` vắng,
   * `""` và `"null"` là hai giá trị CÓ MẶT khác nhau.
   */
  locationProof?: string | null;
  /** Cam kết đọc từ tài liệu genesis trên chuỗi (`onChainCommitment` / `on_chain_commitment`) — 64 ký tự hex. */
  commitment: string;
};

function assertValidSalt(salt: string): void {
  if (typeof salt !== "string" || salt.length !== COMMITMENT_SALT_HEX_LENGTH) {
    throw new Error(
      `salt phải là chuỗi hex ${COMMITMENT_SALT_HEX_LENGTH} ký tự (${COMMITMENT_SALT_BYTES} byte) — ` +
        `nhận ${JSON.stringify(salt)} (${typeof salt === "string" ? salt.length : 0} ký tự). ` +
        `Muối rỗng/thiếu KHÔNG kiểm được — không được coi đó là "khớp".`,
    );
  }
}

function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

/**
 * Tính lại cam kết on-chain từ dữ liệu gốc + muối — bản TypeScript của
 * `AssetCanonical.commitment(salt, physicalIdHash, assetClass, locationProof)`.
 *
 * `sha256(CanonicalMessage(` {@link ASSET_COMMIT_PREFIX} `, salt, physicalIdHash,
 * assetClass, cờ-locationProof, locationProof))`, trả hex thường 64 ký tự.
 *
 * Field cam kết CHỈ có 5 phần tử (salt, physicalIdHash, assetClass, cờ,
 * locationProof) — KHÔNG có `ownerDid`/`nonce` như challenge đúc; đây là hai
 * tiền-ảnh khác nhau cho hai mục đích khác nhau (ký vs. cam kết).
 *
 * @throws Error nếu `salt` rỗng/thiếu hoặc sai độ dài — không tính được tiền-ảnh
 *   thì không được phép giả vờ tính ra một cam kết nào đó.
 */
export function computeAssetCommitment(
  input: Omit<VerifyAssetCommitmentInput, "commitment">,
): string {
  assertValidSalt(input.salt);

  const lp = input.locationProof;
  const absent = lp == null;
  const preimage = canonicalMessage(ASSET_COMMIT_PREFIX, [
    input.salt,
    input.physicalIdHash,
    input.assetClass,
    absent ? LOCATION_ABSENT : LOCATION_PRESENT,
    absent ? "" : lp,
  ]);
  return bytesToHex(sha256(preimage));
}

/**
 * Kiểm cam kết on-chain của một AssetDID — thuần client, KHÔNG gọi mạng.
 *
 * Tính lại cam kết từ `{salt, physicalIdHash, assetClass, locationProof}` rồi
 * so với `commitment` (giá trị đọc từ chuỗi, vd `on_chain_commitment` của
 * {@link AssetModule.checkCommitment}). So sánh không phân biệt hoa/thường —
 * `commitment` do bên gọi cấp có thể đến từ nguồn viết hex khác casing.
 *
 * **Muối rỗng/thiếu ném lỗi, KHÔNG trả `true`.** Không có muối hợp lệ thì
 * không dựng lại được tiền-ảnh — im lặng trả `true` ở đây tương đương xác nhận
 * một tài sản mà thực ra chưa hề kiểm.
 *
 * @throws Error nếu `salt` rỗng/thiếu hoặc sai độ dài (xem {@link computeAssetCommitment}).
 */
export function verifyAssetCommitment(input: VerifyAssetCommitmentInput): boolean {
  const recomputed = computeAssetCommitment(input);
  if (typeof input.commitment !== "string" || input.commitment.length === 0) {
    throw new Error("commitment rỗng/thiếu — không có gì để so sánh");
  }
  return recomputed === input.commitment.toLowerCase();
}

// ─── Commitment-check (GET) ───────────────────────────────────────────────────

/**
 * Sáu trạng thái của `GET /identity/{did}/commitment-check`
 * (`CommitmentCheckStatus.java`). "Khớp/không khớp" là cách chia nói dối —
 * một hàng KHÔNG kiểm được không phải là hàng đã bị sửa, cũng không phải hàng
 * lành; map đủ cả sáu, đừng gộp.
 */
export const COMMITMENT_CHECK_STATUSES = [
  /** Cam kết on-chain khớp cam kết tính lại từ Postgres — hàng chưa bị sửa. */
  "MATCH",
  /** LỆCH — hàng Postgres KHÔNG còn là hàng đã neo tại giao dịch genesis. */
  "MISMATCH",
  /** Tài liệu genesis trên chuỗi không có trường cam kết (đúc trước khi có cam kết) — không kiểm được, mãi mãi. */
  "NO_COMMITMENT_LEGACY",
  /** Trên chuỗi CÓ cam kết nhưng hàng Postgres thiếu muối ⇒ không dựng lại được tiền-ảnh. Phải RỖNG trong sản xuất. */
  "NO_SALT_UNVERIFIABLE",
  /** AssetDID có trong Postgres nhưng chưa neo xong lên chuỗi (`genesis_tx_hash` null) — chưa có gì để đối chiếu. */
  "NOT_ANCHORED",
  /** DID tồn tại nhưng không phải AssetDID — không có cam kết. */
  "NOT_AN_ASSET",
] as const;

/** Một giá trị thuộc {@link COMMITMENT_CHECK_STATUSES}. */
export type CommitmentCheckStatus = (typeof COMMITMENT_CHECK_STATUSES)[number];

/**
 * Kết quả `GET /identity/{did}/commitment-check`.
 *
 * KHÔNG trả `physicalIdHash`/`locationProof` thô (`@JsonInclude(NON_NULL)` bên
 * Java) — bên tra cứu chính đáng đã cầm sẵn ba trường gốc (họ cầm quả trên
 * tay); bên chỉ tò mò không được cấp thêm gì. `commitment_salt` trả kèm để
 * bên ngoài tự băm lại bằng {@link computeAssetCommitment}/{@link verifyAssetCommitment}
 * — không phải tin máy chủ.
 */
export type CommitmentCheckResponse = {
  did: string;
  status: CommitmentCheckStatus;
  /** Cam kết đọc từ tài liệu genesis trên Cardano; `null` khi chưa neo hoặc tài liệu không có trường này. */
  on_chain_commitment: string | null;
  /** Cam kết tính lại từ hàng Postgres + muối; `null` khi thiếu muối nên không tính được. */
  recomputed_commitment: string | null;
  /** Muối 32 byte hex thường của bản ghi; `null` với hàng đúc trước khi có cam kết. */
  commitment_salt: string | null;
  /** Phân loại tài sản — công khai. */
  asset_class: string | null;
  /** Giao dịch neo tài liệu genesis; `null` khi chưa neo. */
  genesis_tx_hash: string | null;
};

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
 * Cố ý KHÔNG nhập vào `ERROR_CODE_MAP` toàn cục ở `fetcher.ts`, và điều kiện để
 * nhập là rõ ràng: **cho tới khi `ErrorCode.java` không còn số nào trùng.**
 * Một bảng toàn cục khoá theo số nguyên chỉ đúng khi số → nghĩa là ánh xạ một-
 * một; hễ còn một số mang hai nghĩa thì bảng ấy dịch sai một trong hai luồng, và
 * dịch sai lặng lẽ — người gọi bắt `err.code` vẫn thấy một cái tên trông hợp lý.
 *
 * Cặp còn trùng hôm nay: **1350** = `DEPENDENCY_CHAIN_CYCLE` (luồng lineage) và
 * `VAULT_ALREADY_EXISTS` (luồng activation vault). Nợ có sẵn trên `main`, chưa
 * gỡ được vì đổi số là phá hợp đồng với client đang chạy.
 *
 * ⚠ **ĐÍNH CHÍNH:** bản trước của bảng này dùng **1353/1354** cho
 * `ASSET_CLASS_NOT_ALLOWED`/`OWNER_KEY_NOT_FOUND` — SAI. `1353-1355` là ba số
 * đã từng ship (`NOT_IN_PHASE2` / `CLAIM_AMOUNT_EXCEEDS_VESTED` /
 * `ALREADY_IN_PHASE2`) rồi bị bỏ theo Wakeme v5 (Issue #67), và được giữ
 * TRỐNG có chủ ý để không đụng client cũ còn cầm mã lỗi in-flight
 * (`ErrorCode.java` dòng 175-179 + dòng 204-211). Dùng lại chúng là gọi tên
 * sai đúng lớp lỗi vừa vá.
 *
 * `1340-1349` (khối `134x`) đã đầy, nên hai mã của luồng asset nằm ở khối MỞ
 * RỘNG `138x`: `ASSET_CLASS_NOT_ALLOWED` = **1380**, `OWNER_KEY_NOT_FOUND` =
 * **1381** (`ErrorCode.java` dòng 220, 231). `1351`/`1352` không phải của luồng
 * asset — chúng thuộc `VAULT_NOT_FOUND`/`POT_UNAVAILABLE` (luồng Activation
 * Vault) và đã bị loại khỏi bảng dưới, có test riêng khẳng định không nhận.
 */
export const ASSET_ERROR_CODES: Record<number, string> = {
  1340: "owner_did_not_found",
  1341: "owner_signature_invalid",
  1342: "physical_id_already_claimed",
  1346: "owner_cannot_own_asset",
  1380: "asset_class_not_allowed",
  1381: "owner_key_not_found",
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
   * **Hai lớp, cần cả hai.** `ownerSignature` chứng minh *chủ sở hữu đồng ý*;
   * `Authorization: Bearer <session-jwt>` chứng minh *phiên gọi hợp lệ*. Không
   * cái nào thay được cái nào — chữ ký owner đi qua tay bất kỳ ai cầm được nó,
   * nên phiên vẫn phải tự đứng ra chịu trách nhiệm cho lời gọi.
   *
   * Cổng Bearer nằm ở `AuthRequiredInterceptor` (mặc-định-từ-chối), không ở
   * `SecurityConfig`: interceptor có ba danh sách miễn trừ
   * (`PUBLIC_ANY_METHOD`/`PUBLIC_GET`/`PUBLIC_POST`), và cái gì không nằm trong
   * đó thì bị chặn. `/identity/asset/create` không nằm trong danh sách nào ⇒
   * bắt buộc Bearer (`AuthRequiredInterceptorTest.assetCreate_noBearer_401`).
   *
   * Thiếu token thì hàm này ném **ngay tại client**, không gửi lên mạng để nhận
   * 401 — một vòng mạng không nói thêm được gì mà người gọi đã biết trước.
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
    // Cổng phiên trước, tải trọng sau: endpoint mặc-định-từ-chối, thiếu Bearer
    // là 401 chắc chắn nên không gửi đi làm gì.
    const token = this._getSessionToken();
    if (!token) throw new Error("No session token — user must login first");

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

    try {
      return await this.fetch<AssetCreateResponse>("/identity/asset/create", {
        method: "POST",
        body: JSON.stringify(body),
        bearerToken: token,
      } as FetchOptions);
    } catch (err) {
      throw refineAssetError(err);
    }
  }

  /**
   * Đối chiếu cam kết on-chain của một AssetDID — `GET /identity/{did}/commitment-check`.
   *
   * **Đòi Bearer, không whitelist.** `/identity/{did}/commitment-check` KHÔNG
   * nằm trong `PUBLIC_GET` của `AuthRequiredInterceptor` — "mặc định đóng, mở
   * từng đường" — nên thiếu để mã bay mãi mãi trên chuỗi. Muối là lớp bảo vệ
   * riêng tư của vị trí vườn (`locationProof`); phát muối công khai vô hiệu
   * hoá đúng lớp bảo vệ đó, nên endpoint đòi phiên đăng nhập dù chấp nhận BẤT
   * KỲ session nào (không khoá theo chủ sở hữu tài sản).
   *
   * Cùng khuôn với {@link createAsset}: thiếu token thì ném **tại client**,
   * không gửi lên mạng để nhận 401.
   *
   * Trả về nguyên `commitment_salt` + `on_chain_commitment` từ server — người
   * gọi tự đối chiếu bằng {@link verifyAssetCommitment} nếu muốn KHÔNG tin vào
   * `status` do server kết luận sẵn.
   *
   * @throws PhoenixKeyError mã chung của fetcher (`timeout`, `network_error`,
   *   `http_<status>`, hoặc mã toàn cục vd `user_did_not_found` cho DID lạ —
   *   bảng {@link ASSET_ERROR_CODES} không áp cho endpoint này).
   */
  async checkCommitment(did: string): Promise<CommitmentCheckResponse> {
    const token = this._getSessionToken();
    if (!token) throw new Error("No session token — user must login first");

    return this.fetch<CommitmentCheckResponse>(
      `/identity/${encodeURIComponent(did)}/commitment-check`,
      {
        method: "GET",
        bearerToken: token,
      } as FetchOptions,
    );
  }
}
