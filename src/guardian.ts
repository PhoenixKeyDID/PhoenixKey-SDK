/**
 * PhoenixKey SDK — Guardian Module
 *
 * Mạng lưới người bảo hộ khôi phục (Social Recovery). Backend:
 * `GuardianController` (`@RequestMapping("/guardians")`).
 *
 * - `add()`    — POST /guardians/add
 * - `remove()` — POST /guardians/remove   (thu hồi mềm: đổi status, không xoá)
 * - `list()`   — GET  /guardians/{userDid}
 *
 * ## Phê duyệt khôi phục KHÔNG đi qua đây
 *
 * PK_DB chỉ giữ **siêu dữ liệu** người bảo hộ. Lượt người bảo hộ ký duyệt một
 * ca khôi phục xảy ra trên Cardano, thẳng vào Smart Contract — không có
 * endpoint nào ở đây làm việc đó. Đừng dựng màn "người bảo hộ bấm duyệt" trên
 * ba đường dưới.
 *
 * ## Ba thứ phải đúng cùng lúc thì một lượt thêm/xoá mới được nhận
 *
 * 1. `proofSignature` — chữ ký DER của **khoá vai owner đang active** thuộc
 *    `userDid`, trên chuỗi byte canonical đóng khung độ dài với tiền tố
 *    `PHOENIXKEY_GUARDIAN_ADD:` / `PHOENIXKEY_GUARDIAN_REMOVE:`, thứ tự trường
 *    `user_did, guardian_did, nonce, op_seq` (API.md §0 + §6). Máy chủ tự
 *    verify — không tin bên gọi tuyến trên đã verify hộ (zero-trust).
 * 2. `nonce` — dùng một lần.
 * 3. `opSeq` — bộ đếm đơn điệu **dùng chung mốc nước với `/keys/*`**, không
 *    phải mốc riêng của guardian. Lấy qua `GET /identity/{did}/op-seq`. Nhỏ
 *    hơn hoặc bằng mốc hiện tại → 409 `op_seq_replay`.
 *
 * SDK **không** dựng chuỗi ký hộ: khoá nằm trong Enclave/ví của người dùng,
 * và khuôn canonical là hợp đồng dây do máy chủ chốt. Bên tích hợp dựng
 * challenge rồi ký, giống mọi luồng ký khác trong thư viện này.
 *
 * ## Mã lỗi phân biệt được (đều là `PhoenixKeyError`)
 *
 * - `guardian_not_found` (4001, 404) · `guardian_already_exists` (4002, 409)
 * - `guardian_self_not_allowed` (4003, 400) — `guardianDid === userDid`.
 *   Chặn tự-khôi-phục đơn phương; **không** phải lỗi chữ ký.
 * - `signature_invalid` (1403, 403) — `proofSignature` không verify được.
 * - `op_seq_replay` (3009, 409) · `op_seq_too_far_ahead` (3010, 400)
 * - `nonce_already_used` (3006, 409)
 * - `user_not_found` (2001, 404)
 * - `unauthorized` (1304) — ở `list()`: thiếu thẻ phiên, hoặc `userDid` khác
 *   chủ phiên (máy chủ trả cùng một mã cho cả hai, xem docstring `list`).
 */

import { createFetcher, FetchOptions } from "./fetcher";

/**
 * Tham số cho một lượt thêm/xoá người bảo hộ.
 *
 * Trường đi camelCase ở đây và được chuyển sang snake_case khi lên dây —
 * cùng quy ước với {@link import("./auth").AuthModule.exchange}.
 */
export type GuardianMutateParams = {
  /** DID của chủ tài khoản đang đổi mạng lưới bảo hộ của chính mình. */
  userDid: string;
  /** DID người được mời/gỡ. Phải KHÁC `userDid` (4003 nếu trùng). */
  guardianDid: string;
  /** Chữ ký DER của khoá vai owner đang active — xem docstring đầu tệp. */
  proofSignature: string;
  /** Chuỗi dùng một lần. */
  nonce: string;
  /** Bộ đếm đơn điệu, dùng chung mốc nước với `/keys/*`. */
  opSeq: number;
};

/** Kết quả `POST /guardians/add` và `POST /guardians/remove`. */
export type GuardianCountResult = {
  /**
   * Số người bảo hộ đang active SAU thao tác. Còn dưới 3 thì màn hình nên
   * cảnh báo: không đủ người thì không khôi phục được tài khoản.
   */
  guardian_count: number;
};

/** Một dòng trong `GET /guardians/{userDid}`. */
export type GuardianEntry = {
  guardian_did: string;
  /** Luôn `"active"` — bảng chỉ trả người đang active. */
  status: string;
  /** ISO-8601. */
  created_at: string;
};

/** Kết quả `GET /guardians/{userDid}`. KHÔNG mang `proof_signature`. */
export type GuardianList = {
  guardians: GuardianEntry[];
  count: number;
};

export class GuardianModule {
  private readonly fetch: ReturnType<typeof createFetcher>;

  constructor(
    private readonly baseUrl: string,
    private readonly _getSessionToken: () => string | null,
  ) {
    this.fetch = createFetcher(baseUrl);
  }

  /**
   * Thêm một người bảo hộ.
   *
   * Máy chủ **không** đòi thẻ phiên ở đường này — thẩm quyền đến từ
   * `proofSignature` của khoá owner, không từ phiên. Một phiên `viewer` bị
   * chiếm cũng không thêm được người bảo hộ nếu không có khoá owner.
   *
   * Khuyến nghị 3–5 người: ít hơn thì không khôi phục nổi, nhiều hơn thì mở
   * rộng bề mặt cho người bảo hộ xấu.
   *
   * @example
   * ```ts
   * const { guardian_count } = await client.guardians.add({
   *   userDid, guardianDid,
   *   proofSignature: await enclave.signGuardianAdd({ userDid, guardianDid, nonce, opSeq }),
   *   nonce, opSeq,
   * });
   * if (guardian_count < 3) warnUser(guardian_count);
   * ```
   */
  async add(params: GuardianMutateParams): Promise<GuardianCountResult> {
    return this.fetch<GuardianCountResult>("/guardians/add", {
      method: "POST",
      body: JSON.stringify(toWire(params)),
    } as FetchOptions);
  }

  /**
   * Gỡ một người bảo hộ — **thu hồi mềm**: hàng không bị xoá khỏi cơ sở dữ
   * liệu, chỉ đổi `status` sang `revoked`, nên vẫn còn dấu vết kiểm toán.
   *
   * Cùng luật chữ ký + nonce + opSeq như {@link add}, chỉ khác tiền tố
   * challenge (`PHOENIXKEY_GUARDIAN_REMOVE:`).
   */
  async remove(params: GuardianMutateParams): Promise<GuardianCountResult> {
    return this.fetch<GuardianCountResult>("/guardians/remove", {
      method: "POST",
      body: JSON.stringify(toWire(params)),
    } as FetchOptions);
  }

  /**
   * Danh sách người bảo hộ đang active — cho màn "Người bảo trợ của tôi".
   *
   * **Chỉ tra được của chính mình.** Thẻ phiên bắt buộc, và `userDid` phải
   * khớp chủ phiên; DID khác trả `unauthorized` (1304) chứ không trả danh
   * sách. Đây là chủ ý: nếu tra được DID bất kỳ thì đường này thành máy lập
   * bản đồ quan hệ giữa người với người — ai bảo hộ ai — từ một danh sách DID
   * công khai.
   *
   * Vì lẽ đó SDK không nhận `userDid` như một tham số tự do được: nó vẫn phải
   * truyền vào để khớp đường dẫn máy chủ, nhưng bên gọi nên lấy từ
   * `client.session.getSessionMeta()?.userDid`, không phải từ ô nhập.
   *
   * Phản hồi KHÔNG mang `proof_signature` của bất kỳ ai.
   *
   * @example
   * ```ts
   * const me = client.session.getSessionMeta()?.userDid;
   * const { guardians, count } = await client.guardians.list(me!);
   * ```
   */
  async list(userDid: string): Promise<GuardianList> {
    const token = this._getSessionToken();
    if (!token) throw new Error("No session token — user must login first");

    return this.fetch<GuardianList>(`/guardians/${encodeURIComponent(userDid)}`, {
      method: "GET",
      bearerToken: token,
    } as FetchOptions);
  }
}

/** camelCase (SDK) → snake_case (dây). Máy chủ đọc SNAKE_CASE toàn cục. */
function toWire(p: GuardianMutateParams): Record<string, string | number> {
  return {
    user_did: p.userDid,
    guardian_did: p.guardianDid,
    proof_signature: p.proofSignature,
    nonce: p.nonce,
    op_seq: p.opSeq,
  };
}
