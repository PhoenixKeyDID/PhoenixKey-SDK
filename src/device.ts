/**
 * PhoenixKey SDK — Device Lifecycle Module
 *
 * "Một người, nhiều thiết bị" self-service — user tự xem/đổi tên/thu hồi các
 * khoá thiết bị (owner/manager/viewer) của chính DID mình.
 *
 * Backend: `DeviceLifecycleController` (`/keys/devices/**`) — session-authenticated
 * (Bearer session_token, KHÔNG chữ ký), đòi vai `owner` cho cả ba đường. Một
 * phiên `manager`/`viewer` gọi bất kỳ hàm nào ở đây nhận `PhoenixKeyError` với
 * `code: "key_role_forbidden"` (HTTP 403) — SDK không tự chặn trước, để backend
 * là nguồn sự thật duy nhất cho quyền.
 */

import { createFetcher, FetchOptions } from "./fetcher";
import { DeviceListResponse, DeviceView } from "./types";

export class DeviceModule {
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
   * Danh sách thiết bị/khoá của chính DID đang đăng nhập — kể cả đã revoked
   * (lịch sử). Đòi phiên vai `owner`; `manager`/`viewer` → `PhoenixKeyError`
   * `code: "key_role_forbidden"`.
   *
   * @example
   * ```ts
   * const { devices } = await client.devices.listDevices();
   * const thisDevice = devices.find((d) => d.current);
   * ```
   */
  async listDevices(): Promise<DeviceListResponse> {
    return this.fetch<DeviceListResponse>("/keys/devices", {
      method: "GET",
      bearerToken: this.requireToken(),
    } as FetchOptions);
  }

  /**
   * Đặt/đổi tên một thiết bị theo `keyId` (từ {@link DeviceView.key_id}).
   *
   * Lỗi có thể gặp (đều `PhoenixKeyError`):
   * - `code: "key_role_forbidden"` (403) — phiên không phải `owner`.
   * - `code: "device_name_invalid"` (400) — tên rỗng-sau-trim, quá 100 ký
   *   tự, hoặc chứa ký tự điều khiển.
   * - `code: "key_not_found"` (404) — `keyId` không tồn tại, hoặc không
   *   thuộc DID này (cố ý trả 404 thay vì 403 để không lộ keyId có tồn tại).
   */
  async renameDevice(keyId: string, deviceName: string): Promise<DeviceView> {
    return this.fetch<DeviceView>(`/keys/devices/${encodeURIComponent(keyId)}/name`, {
      method: "POST",
      bearerToken: this.requireToken(),
      body: JSON.stringify({ device_name: deviceName }),
    } as FetchOptions);
  }

  /**
   * Thu hồi một thiết bị theo `keyId`. Không cần chữ ký — chỉ cần phiên
   * `owner` hợp lệ. Sau khi thu hồi, phiên của thiết bị đó chết ngay lượt gọi
   * kế tiếp.
   *
   * Lỗi có thể gặp (đều `PhoenixKeyError`):
   * - `code: "key_role_forbidden"` (403) — phiên không phải `owner`.
   * - `code: "key_not_found"` (404) — `keyId` không tồn tại/không thuộc DID này.
   * - `code: "last_owner_key"` (409) — đây là khoá `owner` active cuối cùng
   *   (kể cả tự thu hồi chính thiết bị đang gọi) — đi account recovery thay
   *   vì revoke.
   */
  async revokeDevice(keyId: string): Promise<void> {
    await this.fetch<void>(`/keys/devices/${encodeURIComponent(keyId)}/revoke`, {
      method: "POST",
      bearerToken: this.requireToken(),
    } as FetchOptions);
  }
}
