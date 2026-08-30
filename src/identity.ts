/**
 * PhoenixKey SDK — Identity Module
 *
 * DID resolution + pubkey lookup + dashboard health.
 * Backend endpoints: GET /identity/{did}/{pubkey,status,document}, GET /identity/health.
 */

import { createFetcher, FetchOptions } from "./fetcher";
import {
  IdentityPubkey,
  IdentityStatus,
  IdentityHealth,
  UsernameResolve,
  W3CDIDDocument,
  PhoenixKeyError,
} from "./types";

export class IdentityModule {
  private readonly fetch: ReturnType<typeof createFetcher>;

  constructor(
    private readonly baseUrl: string,
    private readonly _getSessionToken: () => string | null,
  ) {
    this.fetch = createFetcher(baseUrl);
  }

  /**
   * Lookup owner public key của một DID. Public — không cần auth.
   * Use case: 3rd-party backend verify chữ ký Hardware Key của user.
   */
  async getPubkey(userDid: string): Promise<IdentityPubkey> {
    return this.fetch<IdentityPubkey>(`/identity/${encodeURIComponent(userDid)}/pubkey`);
  }

  /**
   * TAAD state hiện tại từ cache `onchain_taad_state_cache`.
   * Status: ACTIVE | RECOVERING | MIGRATED.
   */
  async getStatus(userDid: string): Promise<IdentityStatus> {
    return this.fetch<IdentityStatus>(`/identity/${encodeURIComponent(userDid)}/status`);
  }

  /**
   * Resolve W3C DID Document từ Cardano qua Blockfrost (server-side resolve).
   * Field naming là camelCase per W3C spec.
   */
  async resolveDID(userDid: string): Promise<W3CDIDDocument> {
    return this.fetch<W3CDIDDocument>(`/identity/${encodeURIComponent(userDid)}/document`);
  }

  /**
   * Resolve username → DID. Public — không cần auth.
   *
   * Ném `PhoenixKeyError` code `user_not_found` khi tên chưa ai giữ. Cần phân
   * biệt "không có" với lỗi mạng mà không phải bọc try/catch thì dùng
   * {@link lookupUsername}.
   *
   * Tên được so khớp sau khi hạ chữ thường — backend chuẩn hoá bằng
   * `Locale.ROOT`, nên không phụ thuộc locale của máy gọi.
   */
  async resolveByUsername(username: string): Promise<UsernameResolve> {
    return this.fetch<UsernameResolve>(
      `/identity/by-username/${encodeURIComponent(username)}`,
    );
  }

  /**
   * Như {@link resolveByUsername} nhưng trả `null` thay vì ném, khi và CHỈ khi
   * backend nói rõ là không tìm thấy (`user_not_found`). Mọi lỗi khác — mạng
   * hỏng, hết giờ, 5xx — vẫn ném.
   *
   * Tách hai đường vì "chưa ai giữ tên này" là kết quả **bình thường** khi tra
   * một cái tên, không phải sự cố; bắt mọi lời gọi bọc try/catch thì sớm muộn
   * có người bọc rộng tay và nuốt luôn lỗi mạng thành "không có tên".
   *
   * ⚠ **`null` KHÔNG có nghĩa là tên còn trống để đặt.** Bất biến "một tên ↔
   * một DID, vĩnh viễn" chặn cả tên đã bị thả ra, mà luật đó nằm ở bảng
   * `username_history` — endpoint này không soi bảng đó. Một cái tên đã có chủ
   * cũ trả về `null` ở đây rồi ném `409 USERNAME_TAKEN` lúc đặt. Đừng dựng màn
   * hình "tên này còn trống ✓" trên hàm này; endpoint kiểm-đặt-được đang chờ
   * làm (PhoenixKey-Database issue #188).
   */
  async lookupUsername(username: string): Promise<UsernameResolve | null> {
    try {
      return await this.resolveByUsername(username);
    } catch (err) {
      if (err instanceof PhoenixKeyError && err.code === "user_not_found") return null;
      throw err;
    }
  }

  /**
   * Dashboard health snapshot (spec §9.5). Bearer session_token bắt buộc.
   * Trả về `{ seed_exported, exported_at, active_key_count, guardian_count }`.
   */
  async getHealth(): Promise<IdentityHealth> {
    const token = this._getSessionToken();
    if (!token) throw new Error("No session token — user must login first");

    return this.fetch<IdentityHealth>("/identity/health", {
      method: "GET",
      bearerToken: token,
    } as FetchOptions);
  }
}
