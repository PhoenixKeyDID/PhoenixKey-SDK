/**
 * PhoenixKey SDK — Activity Logs Module
 *
 * Cursor-paginated audit trail (spec §10 + API.md §6).
 * Bearer session_token bắt buộc. Zero-PII: backend tự truncate user_id +
 * mask ip_hash trước khi trả về.
 */

import { createFetcher, FetchOptions } from "./fetcher";
import { ActivityLogPage, ActivityLogQuery } from "./types";

export class ActivityModule {
  private readonly fetch: ReturnType<typeof createFetcher>;

  constructor(
    private readonly baseUrl: string,
    private readonly _getSessionToken: () => string | null,
  ) {
    this.fetch = createFetcher(baseUrl);
  }

  /**
   * List activity logs của user hiện tại.
   *
   * @param opts.limit   1-100 (default 20)
   * @param opts.cursor  UUID id của item cuối trang trước
   * @param opts.filter  action name (vd "key_rotated", "sign_request_approved")
   * @param opts.range   "7d" | "30d" | "all" (default "all")
   *
   * @example
   * ```ts
   * // Pagination loop
   * let cursor: string | undefined;
   * do {
   *   const page = await client.activity.list({ limit: 50, cursor, range: "30d" });
   *   page.logs.forEach(renderRow);
   *   cursor = page.next_cursor ?? undefined;
   * } while (cursor);
   * ```
   */
  async list(opts: ActivityLogQuery = {}): Promise<ActivityLogPage> {
    const token = this._getSessionToken();
    if (!token) throw new Error("No session token — user must login first");

    const params = new URLSearchParams();
    if (opts.limit !== undefined) params.set("limit", String(opts.limit));
    if (opts.cursor) params.set("cursor", opts.cursor);
    if (opts.filter) params.set("filter", opts.filter);
    if (opts.range) params.set("range", opts.range);

    const qs = params.toString();
    const path = `/activity-logs${qs ? `?${qs}` : ""}`;

    return this.fetch<ActivityLogPage>(path, {
      method: "GET",
      bearerToken: token,
    } as FetchOptions);
  }
}
