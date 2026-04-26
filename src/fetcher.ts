/**
 * PhoenixKey SDK — Internal Fetch Wrapper
 *
 * Extends the frontend apiFetch pattern with:
 * - Mandatory `x-api-key` header on every request
 * - Optional `Authorization: Bearer <session_token>` for authed routes
 * - Throws `PhoenixKeyError` on non-2xx or network failure
 */

import { PhoenixKeyError } from "./types";

export type FetchOptions = RequestInit & {
  baseUrl?: string;
  /** Attach Authorization: Bearer <token> (pass the session_token) */
  sessionToken?: string;
  /** Parse response as JSON (default: true). Set false for SSE. */
  json?: boolean;
};

export function createFetcher(apiKey: string, defaultBaseUrl: string) {
  return async function sdkFetch<T = unknown>(
    path: string,
    opts: FetchOptions = {},
  ): Promise<T> {
    const { baseUrl, sessionToken, json = true, headers, ...rest } = opts;

    const base = (baseUrl ?? defaultBaseUrl).replace(/\/+$/, "");
    const normalizedPath = path.startsWith("/") ? path : `/${path}`;
    const url = /^https?:\/\//.test(path) ? path : `${base}${normalizedPath}`;

    const finalHeaders: Record<string, string> = {
      Accept: "application/json",
      "x-api-key": apiKey,
      ...(rest.body && !(rest.body instanceof FormData)
        ? { "Content-Type": "application/json" }
        : {}),
      ...((headers as Record<string, string>) ?? {}),
    };

    if (sessionToken) {
      finalHeaders.Authorization = `Bearer ${sessionToken}`;
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

    if (!res.ok) {
      let code: string | undefined;
      let details: unknown;
      let serverMessage: string | undefined;
      try {
        const body = await res.json();
        code = body?.code;
        serverMessage = body?.message;
        details = body;
      } catch {
        /* body not JSON */
      }
      throw new PhoenixKeyError({
        status: res.status,
        code,
        message: serverMessage ?? res.statusText,
        details,
      });
    }

    if (!json || res.status === 204) return undefined as T;

    try {
      return (await res.json()) as T;
    } catch (err) {
      throw new PhoenixKeyError({
        status: res.status,
        code: "invalid_json",
        message: "Response was not valid JSON",
      });
    }
  };
}