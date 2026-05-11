/**
 * PhoenixKey SDK — Internal Fetch Wrapper
 *
 * Handles backend conventions:
 * - Unwraps `DataResponse { code, message, result }` envelope
 * - Maps integer error codes (1301, 1302, ...) → string codes ("session_expired", ...)
 * - Throws `PhoenixKeyError` on non-2xx, code != 1000, or network failure
 */

import { PhoenixKeyError } from "./types";

export type FetchOptions = RequestInit & {
  /** Override base URL for this request. */
  baseUrl?: string;
  /** Attach Authorization: Bearer <token>. */
  bearerToken?: string;
  /** Parse response as JSON (default: true). Set false for SSE. */
  json?: boolean;
};

/**
 * Backend integer error code → string code mapping.
 * Source: PhoenixKey-Database `exception/ErrorCode.java`.
 */
export const ERROR_CODE_MAP: Record<number, string> = {
  1301: "session_not_found",
  1302: "session_expired",
  1303: "session_already_approved",
  1401: "sign_request_not_found",
  1402: "sign_request_expired",
  1403: "signature_invalid",
  2001: "user_not_found",
  2002: "user_did_not_found",
  2003: "user_did_already_exists",
  3001: "key_already_authorized",
  3002: "key_not_found",
  3003: "key_signature_invalid",
  3004: "key_already_revoked",
  3005: "key_status_invalid",
  3006: "nonce_already_used",
  4001: "guardian_not_found",
  4002: "guardian_already_exists",
  4003: "guardian_signature_invalid",
  4004: "guardian_insufficient",
  4005: "guardian_already_revoked",
  5001: "taad_state_not_found",
  5002: "taad_state_stale",
  5003: "taad_reorg_detected",
  5004: "taad_in_recovery_mode",
  5005: "taad_sequence_mismatch",
  5101: "cardano_tx_failed",
  5102: "cardano_resolve_failed",
  9800: "enum_invalid_value",
  9998: "system_unknown_error",
  9999: "internal_error",
};

/**
 * Backend response envelope shape.
 * Success: `{ code: 1000, message, result: <T> }` — fetcher returns `result`.
 * Error: non-2xx HTTP với body `{ code: <int>, message }` — fetcher throws.
 */
type DataResponse<T> = {
  code: number;
  message: string;
  result?: T;
};

export function createFetcher(defaultBaseUrl: string) {
  return async function sdkFetch<T = unknown>(
    path: string,
    opts: FetchOptions = {},
  ): Promise<T> {
    const { baseUrl, bearerToken, json = true, headers, ...rest } = opts;

    const base = (baseUrl ?? defaultBaseUrl).replace(/\/+$/, "");
    const normalizedPath = path.startsWith("/") ? path : `/${path}`;
    const url = /^https?:\/\//.test(path) ? path : `${base}${normalizedPath}`;

    const finalHeaders: Record<string, string> = {
      Accept: "application/json",
      ...(rest.body && !(rest.body instanceof FormData)
        ? { "Content-Type": "application/json" }
        : {}),
      ...((headers as Record<string, string>) ?? {}),
    };

    if (bearerToken) {
      finalHeaders.Authorization = `Bearer ${bearerToken}`;
    }

    let res: Response;
    try {
      res = await fetch(url, { ...rest, headers: finalHeaders });
    } catch (err) {
      throw new PhoenixKeyError({
        status: 0,
        code: "network_error",
        message: err instanceof Error ? err.message : String(err),
      });
    }

    // Non-2xx → parse error body if JSON, throw PhoenixKeyError
    if (!res.ok) {
      let rawCode: number | undefined;
      let serverMessage: string | undefined;
      let details: unknown;
      try {
        const body = (await res.json()) as DataResponse<unknown>;
        rawCode = typeof body?.code === "number" ? body.code : undefined;
        serverMessage = body?.message;
        details = body;
      } catch {
        /* body not JSON */
      }
      throw new PhoenixKeyError({
        status: res.status,
        rawCode,
        code:
          rawCode !== undefined && ERROR_CODE_MAP[rawCode]
            ? ERROR_CODE_MAP[rawCode]
            : `http_${res.status}`,
        message: serverMessage ?? res.statusText,
        details,
      });
    }

    if (!json || res.status === 204) return undefined as T;

    let body: DataResponse<T>;
    try {
      body = (await res.json()) as DataResponse<T>;
    } catch (err) {
      throw new PhoenixKeyError({
        status: res.status,
        code: "invalid_json",
        message: "Response was not valid JSON",
      });
    }

    // Unwrap DataResponse envelope. Backend luôn dùng pattern này — không
    // có endpoint nào trả raw shape (verified với API.md cross-check).
    if (body && typeof body === "object" && "code" in body) {
      if (body.code !== 1000) {
        throw new PhoenixKeyError({
          status: res.status,
          rawCode: body.code,
          code: ERROR_CODE_MAP[body.code] ?? `code_${body.code}`,
          message: body.message ?? "Unknown error",
          details: body,
        });
      }
      return (body.result ?? (undefined as unknown)) as T;
    }

    // Fallback: raw response (shouldn't happen với current backend, nhưng
    // safe defensive — chấp nhận bất kỳ JSON shape nào).
    return body as unknown as T;
  };
}
