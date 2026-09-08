/**
 * PhoenixKey SDK — OrgDID Module
 *
 * Vòng đời danh tính tổ chức. Backend: `OrgController`
 * (`@RequestMapping("/identity/org")`).
 *
 * | Phương thức | Đường | Thẻ phiên |
 * |---|---|---|
 * | `list()`              | GET  `/identity/org`                              | có |
 * | `create()`            | POST `/identity/org/create`                       | không |
 * | `found()`             | POST `/identity/org/founding`                     | không |
 * | `upgradeAuthority()`  | POST `/identity/org/{orgDid}/upgrade-authority`   | không |
 * | `issueLampGrant()`    | POST `/identity/org/{orgDid}/mint-lamp`           | không |
 * | `listLampGrants()`    | GET  `/identity/org/{orgDid}/grants`              | có |
 * | `consumeLampGrant()`  | POST `/identity/org/grants/{grantId}/consume`     | không¹ |
 * | `revokeLampGrant()`   | POST `/identity/org/{orgDid}/grants/{grantId}/revoke` | không |
 *
 * ¹ Không dùng thẻ phiên mà dùng khoá kho bạc cấu hình sẵn phía máy chủ — xem
 * {@link OrgModule.consumeLampGrant}.
 *
 * Bốn đường ghi ở giữa **không** dùng thẻ phiên: thẩm quyền đến từ chữ ký của
 * khoá vai owner, không từ phiên đăng nhập. Chiếm được phiên không đúc được
 * tổ chức.
 *
 * ## Chữ ký là hợp đồng dây, SDK không dựng hộ
 *
 * Mọi `ownerSignature` dưới đây ký trên **chuỗi byte canonical đóng khung độ
 * dài** (API.md §0), tiền tố riêng cho từng luồng (`PHOENIXKEY_ORG_MINT:`,
 * `PHOENIXKEY_ORG_FOUNDING:`, `PHOENIXKEY_ORG_UPGRADE:`,
 * `PHOENIXKEY_ORG_LAMP:`). Khuôn nối `:` đời cũ đã bị máy chủ từ chối. SDK cố
 * ý không dựng chuỗi này: khoá nằm trong Enclave, và một bản dựng lệch phiên
 * bản trong thư viện khách sẽ làm cả luồng chết câm mà không ai biết vì sao.
 *
 * ## Grant LAMP: đây là giấy uỷ quyền, KHÔNG phải lượt đúc tiền
 *
 * `issueLampGrant()` không đúc LAMP và không nộp giao dịch nào lên Cardano.
 * Nó phát một **Grant tự-verify** nói rằng người kiểm soát OrgDID cho phép một
 * thao tác LAMP cụ thể. Công cụ ngoài (`dist_treasury` của MagicLamp) mới ráp,
 * ký và nộp giao dịch thật. Cầm Grant trong tay **không** có nghĩa LAMP đã
 * chảy — phía tiêu Grant nằm ngoài kho này. Tổng cung LAMP cố định 36 tỷ.
 *
 * `amount_lamp` là **chuỗi thập phân** đơn vị oildrop, không phải số. Tổng
 * cung 3,6×10¹⁶ oildrop vượt `Number.MAX_SAFE_INTEGER`; đưa qua `Number()` là
 * mất chữ số ở hàng thấp mà không có gì báo.
 */

import { createFetcher, FetchOptions } from "./fetcher";

// ─── Danh sách tổ chức ───────────────────────────────────────────────────────

export type OrgSummary = {
  org_did: string;
  name: string;
  /** `"single"` (một chủ) hoặc `"threshold"` (m-of-n). */
  authority_model: string;
  /** Null khi `authority_model === "single"`. */
  threshold: number | null;
  /** `"owner"` (sở hữu) hoặc `"member"` (đồng kiểm soát m-of-n). */
  role: string;
  /** ISO-8601. */
  created_at: string;
};

/** Kết quả `GET /identity/org`. Chưa gắn tổ chức nào → `orgs: []`, không 404. */
export type OrgList = {
  orgs: OrgSummary[];
};

// ─── Đúc / nâng thẩm quyền ───────────────────────────────────────────────────

export type OrgCreateParams = {
  /** DID người sở hữu duy nhất, khuôn `did:phoenix:<b32-13>:<hex-64>`. */
  ownerDid: string;
  /** 1–100 ký tự. */
  name: string;
  /** Tuỳ chọn, ≤ 50 ký tự. Giữ mã hoá AES-GCM khi lưu; không bao giờ trả về. */
  registrationNumber?: string;
  /** Chữ ký của `ownerDid` trên challenge `PHOENIXKEY_ORG_MINT:`. */
  ownerSignature: string;
  /** 1–64 ký tự, dùng một lần. */
  nonce: string;
};

export type OrgCreateResult = {
  org_did: string;
  owner_did: string;
  tx_hash: string;
};

/** Một người đồng sáng lập trong luồng m-of-n. */
export type OrgFounderInput = {
  ownerDid: string;
  ownerSignature: string;
};

export type OrgFoundingParams = {
  /** 1–16 người. Mỗi người ký RIÊNG cùng một challenge canonical. */
  founders: OrgFounderInput[];
  /** m — phải ≥ 2 (m = 1 thì dùng {@link OrgModule.create}) và ≤ số founder. */
  threshold: number;
  name: string;
  /**
   * Tuỳ chọn. **Nằm TRONG chữ ký** — trước kia nó không được ký, nên ba người
   * ký tên tổ chức mà người nộp gắn mã số đăng ký của công ty khác thì cả ba
   * chữ ký vẫn qua.
   */
  registrationNumber?: string;
  nonce: string;
};

export type OrgFoundingResult = {
  org_did: string;
  founders: string[];
  threshold: number;
  tx_hash: string;
};

export type OrgUpgradeAuthorityParams = {
  /** Chủ sở hữu duy nhất hiện tại. */
  currentOwnerDid: string;
  /** Chữ ký của chủ hiện tại trên challenge `PHOENIXKEY_ORG_UPGRADE:`. */
  ownerSignature: string;
  /** 1–15 thành viên mới; mỗi người tự đồng ý bằng chữ ký riêng. */
  newMembers: OrgFounderInput[];
  /** m mới, ≥ 2. */
  newThreshold: number;
  nonce: string;
};

export type OrgUpgradeAuthorityResult = {
  org_did: string;
  members: string[];
  threshold: number;
  tx_hash: string;
};

// ─── Grant uỷ quyền LAMP ─────────────────────────────────────────────────────

/** Ba giai đoạn dòng LAMP. Máy chủ chỉ nhận đúng ba giá trị này. */
export type OrgLampGrantAction = "mint:LAMP" | "pot:fund" | "pot:distribute";

export type OrgLampGrantParams = {
  action: OrgLampGrantAction;
  /** Đích của thao tác (địa chỉ kho / id pot / id chiến dịch), ≤ 200 ký tự. */
  resource: string;
  /** CHUỖI thập phân oildrop, `^[1-9][0-9]{0,25}$`. Đừng đưa qua `Number()`. */
  amountLamp: string;
  /**
   * Tuỳ chọn — DID được phép tiêu Grant. **Bỏ trống = năng lực mang-là-dùng:
   * ai cầm Grant cũng trình được.** Nên luôn đặt bằng DID của người vận hành
   * `dist_treasury`, để lộ Grant không tự động thành mất tiền.
   */
  granteeDid?: string;
  /**
   * Tuỳ chọn, 60–604800 giây. Máy chủ tự tính `valid_from_slot` từ đỉnh chuỗi
   * hiện tại — bên gọi không cần đồng hồ slot. Bỏ trống = Grant không có hạn
   * cứng (chỉ còn nonce dùng-một-lần chặn phát lại).
   */
  validTtlSeconds?: number;
  /** Người kiểm soát OrgDID hiện tại. */
  ownerDid: string;
  ownerSignature: string;
  /**
   * 1–64 ký tự. **Mốc dùng-một-lần ở đây là VĨNH VIỄN**: ngoài bảng nonce có
   * hạn 10 phút còn có ràng buộc duy nhất `(signer_did, nonce)` trên chính
   * bảng Grant, mà bảng Grant không bao giờ bị dọn. Nộp lại một thân yêu cầu
   * cũ sau khi nonce hết hạn KHÔNG phát Grant mới — nhận `nonce_already_used`.
   */
  nonce: string;
};

export type OrgLampGrant = {
  grant_id: string;
  grantor_did: string;
  grantee_did: string | null;
  action: string;
  resource: string;
  /** Chuỗi thập phân oildrop. */
  amount_lamp: string;
  valid_from_slot: number;
  valid_until_slot: number | null;
  nonce: string;
  status: string;
  signer_did: string;
  signer_public_key_hex: string;
  signature: string;
  canonical_challenge_hex: string;
  revocable: boolean;
};

export type OrgLampGrantSummary = {
  grant_id: string;
  grantee_did: string | null;
  action: string;
  resource: string;
  amount_lamp: string;
  valid_from_slot: number;
  valid_until_slot: number | null;
  /** `ISSUED | CONSUMED | REVOKED | EXPIRED` — xem {@link OrgModule.listLampGrants}. */
  status: string;
  consumed_at: string | null;
  consumed_tx_hash: string | null;
  revoked_at: string | null;
  created_at: string;
};

export type OrgLampGrantList = {
  grants: OrgLampGrantSummary[];
};

export type OrgLampGrantConsumeParams = {
  /** Hash giao dịch đã nộp, 64 ký tự hex. */
  txHash: string;
  nonce: string;
  /** Chữ ký của khoá kho bạc cấu hình phía máy chủ. */
  consumerSignature: string;
};

export type OrgLampGrantConsumeResult = {
  grant_id: string;
  org_did: string;
  status: string;
  consumed_at: string;
  consumed_tx_hash: string;
};

export type OrgLampGrantRevokeParams = {
  ownerDid: string;
  ownerSignature: string;
  nonce: string;
};

export type OrgLampGrantRevokeResult = {
  grant_id: string;
  org_did: string;
  status: string;
  revoked_at: string;
  revoked_by_did: string;
};

export class OrgModule {
  private readonly fetch: ReturnType<typeof createFetcher>;

  constructor(
    private readonly baseUrl: string,
    private readonly _getSessionToken: () => string | null,
  ) {
    this.fetch = createFetcher(baseUrl);
  }

  private requireToken(): string {
    const token = this._getSessionToken();
    if (!token) throw new Error("No session token — user must login first");
    return token;
  }

  /**
   * Danh sách OrgDID của **chính người gọi**.
   *
   * Không nhận tham số nào, và đó là chủ ý: DID lấy từ thẻ phiên. Cho bên gọi
   * bơm `?owner_did=` vào là dựng lại đúng máy lập bản đồ người → tổ chức mà
   * `/wallet` vừa đóng lại.
   *
   * Gộp hai nguồn rồi khử trùng theo `org_did`; vừa sở hữu vừa là thành viên
   * thì trả `role: "owner"`. Chưa gắn tổ chức nào → `orgs: []`, không phải 404.
   * **Không** trả `registration_number`.
   */
  async list(): Promise<OrgList> {
    return this.fetch<OrgList>("/identity/org", {
      method: "GET",
      bearerToken: this.requireToken(),
    } as FetchOptions);
  }

  /** Đúc OrgDID một chủ sở hữu (TNHH 1 TV). Nâng lên m-of-n sau bằng {@link upgradeAuthority}. */
  async create(params: OrgCreateParams): Promise<OrgCreateResult> {
    const body: Record<string, string> = {
      owner_did: params.ownerDid,
      name: params.name,
      owner_signature: params.ownerSignature,
      nonce: params.nonce,
    };
    if (params.registrationNumber !== undefined) {
      body.registration_number = params.registrationNumber;
    }
    return this.fetch<OrgCreateResult>("/identity/org/create", {
      method: "POST",
      body: JSON.stringify(body),
    } as FetchOptions);
  }

  /**
   * Đúc OrgDID thuộc quyền m-of-n: **tất cả n** người sáng lập cùng ký một
   * challenge canonical (danh sách DID sắp xếp theo thứ tự từ điển). Máy chủ
   * verify đủ n chữ ký ở tầng ứng dụng; validator on-chain sau đó chỉ đòi ≥ m.
   */
  async found(params: OrgFoundingParams): Promise<OrgFoundingResult> {
    const body: Record<string, unknown> = {
      founders: params.founders.map((f) => ({
        owner_did: f.ownerDid,
        owner_signature: f.ownerSignature,
      })),
      threshold: params.threshold,
      name: params.name,
      nonce: params.nonce,
    };
    if (params.registrationNumber !== undefined) {
      body.registration_number = params.registrationNumber;
    }
    return this.fetch<OrgFoundingResult>("/identity/org/founding", {
      method: "POST",
      body: JSON.stringify(body),
    } as FetchOptions);
  }

  /**
   * Nâng thẩm quyền từ một-chủ lên ngưỡng m-of-n.
   *
   * Chỉ đổi phần thẩm quyền; DID và các trường bất biến giữ nguyên. **Không có
   * đường hạ xuống** — tổ chức đã thành m-of-n thì trả
   * `org_authority_not_upgradable` (1345, 409) nếu gọi lại.
   */
  async upgradeAuthority(
    orgDid: string,
    params: OrgUpgradeAuthorityParams,
  ): Promise<OrgUpgradeAuthorityResult> {
    return this.fetch<OrgUpgradeAuthorityResult>(
      `/identity/org/${encodeURIComponent(orgDid)}/upgrade-authority`,
      {
        method: "POST",
        body: JSON.stringify({
          current_owner_did: params.currentOwnerDid,
          owner_signature: params.ownerSignature,
          new_members: params.newMembers.map((m) => ({
            owner_did: m.ownerDid,
            owner_signature: m.ownerSignature,
          })),
          new_threshold: params.newThreshold,
          nonce: params.nonce,
        }),
      } as FetchOptions,
    );
  }

  /**
   * Phát Grant uỷ quyền một thao tác LAMP.
   *
   * **Không đúc LAMP, không nộp giao dịch** — xem phần "Grant LAMP" ở đầu tệp.
   *
   * ⚠ **Chỉ tổ chức `authority_model="single"` dùng được.** Tổ chức đã nâng
   * lên m-of-n nhận `org_grant_unsupported` (1348, 409): đường ký cho ngưỡng
   * nhiều người ở luồng Grant chưa có phía máy chủ. Đây là khoảng trống đo
   * được ở `OrgServiceImpl.issueLampGrant`, không phải giới hạn thiết kế.
   *
   * Lỗi hay gặp: `owner_signature_invalid` (1341, 403) khi người ký không phải
   * người kiểm soát hiện tại · `nonce_already_used` (3006, 409) ·
   * `org_grant_invalid` (1349, 400).
   */
  async issueLampGrant(
    orgDid: string,
    params: OrgLampGrantParams,
  ): Promise<OrgLampGrant> {
    const body: Record<string, unknown> = {
      action: params.action,
      resource: params.resource,
      amount_lamp: params.amountLamp,
      owner_did: params.ownerDid,
      owner_signature: params.ownerSignature,
      nonce: params.nonce,
    };
    if (params.granteeDid !== undefined) body.grantee_did = params.granteeDid;
    if (params.validTtlSeconds !== undefined) {
      body.valid_ttl_seconds = params.validTtlSeconds;
    }
    return this.fetch<OrgLampGrant>(
      `/identity/org/${encodeURIComponent(orgDid)}/mint-lamp`,
      { method: "POST", body: JSON.stringify(body) } as FetchOptions,
    );
  }

  /**
   * Liệt kê Grant LAMP của một tổ chức. Chỉ người kiểm soát hiện tại đọc
   * được — người khác nhận `unauthorized` (1304).
   *
   * `status` được **tính lại theo slot hiện tại**: một Grant còn `ISSUED`
   * trong bảng mà đã qua `valid_until_slot` báo về là `EXPIRED`. Đừng lưu lại
   * `status` rồi dùng sau — nó là hàm của thời điểm hỏi.
   */
  async listLampGrants(orgDid: string): Promise<OrgLampGrantList> {
    return this.fetch<OrgLampGrantList>(
      `/identity/org/${encodeURIComponent(orgDid)}/grants`,
      { method: "GET", bearerToken: this.requireToken() } as FetchOptions,
    );
  }

  /**
   * Báo rằng một Grant đã được ráp + nộp thành giao dịch thật.
   *
   * ⚠ **Đây không phải đường cho ứng dụng người dùng.** Người gọi hợp lệ là
   * người vận hành `dist_treasury`, và máy chủ xác thực bằng **khoá công khai
   * cấu hình sẵn** (`phoenixkey.lamp.treasury-public-key-hex`), không phải thẻ
   * phiên. Khoá đó chưa cấu hình thì đường này **đóng kín**: trả 503
   * `grant_consumer_key_not_configured` (1377) cho mọi lời gọi — cố ý hỏng về
   * phía an toàn, không phải sự cố tạm thời.
   *
   * Bất biến theo `txHash`: gọi lại đúng `txHash` trên một Grant đã `CONSUMED`
   * trả 200 và không đổi gì; `txHash` khác trả `grant_already_consumed`
   * (1373, 409).
   */
  async consumeLampGrant(
    grantId: string,
    params: OrgLampGrantConsumeParams,
  ): Promise<OrgLampGrantConsumeResult> {
    return this.fetch<OrgLampGrantConsumeResult>(
      `/identity/org/grants/${encodeURIComponent(grantId)}/consume`,
      {
        method: "POST",
        body: JSON.stringify({
          tx_hash: params.txHash,
          nonce: params.nonce,
          consumer_signature: params.consumerSignature,
        }),
      } as FetchOptions,
    );
  }

  /**
   * Thu hồi một Grant **chưa tiêu**. Cùng người ký như {@link issueLampGrant}
   * — người kiểm soát hiện tại của OrgDID.
   *
   * Grant đã `CONSUMED` không thu hồi được (`grant_already_consumed`, 1373):
   * giao dịch đã lên chuỗi rồi, giấy uỷ quyền rút lại cũng không kéo nó về.
   * Thu hồi hai lần → `grant_already_revoked` (1374).
   */
  async revokeLampGrant(
    orgDid: string,
    grantId: string,
    params: OrgLampGrantRevokeParams,
  ): Promise<OrgLampGrantRevokeResult> {
    return this.fetch<OrgLampGrantRevokeResult>(
      `/identity/org/${encodeURIComponent(orgDid)}/grants/${encodeURIComponent(grantId)}/revoke`,
      {
        method: "POST",
        body: JSON.stringify({
          owner_did: params.ownerDid,
          owner_signature: params.ownerSignature,
          nonce: params.nonce,
        }),
      } as FetchOptions,
    );
  }
}
