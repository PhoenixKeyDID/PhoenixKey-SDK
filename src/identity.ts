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
  W3CDIDDocument,
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
