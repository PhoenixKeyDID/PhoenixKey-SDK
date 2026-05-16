/**
 * PhoenixKey SDK — Activation Module
 *
 * Buy the activation package (200,000₫ → 1001 LAMP + 10 ADA) via a Genie
 * agent. The flow has 4 phases:
 *
 *   1. `initiate()` — server matches a Genie, returns payment QR + ProofChat URL
 *   2. (user pays 200k via VietQR or other off-chain channel)
 *   3. (Genie's mobile app signs the Cardano tx and submits)
 *   4. SSE event "activated" fires → balance reflects new LAMP + ADA
 *
 * Use `openEventStream()` to listen for lifecycle events in real time.
 */

import { createFetcher, FetchOptions } from "./fetcher";
import { ResilientSSE, SseOptions } from "./sse";
import { SseHandlers } from "./types";

export type ActivationSession = {
  activation_id: string;
  payment_qr_url: string;
  amount_vnd: number;
  amount_lamp: number;
  amount_lovelace: number;
  genie_did: string;
  proof_chat_url: string;
  expires_at: number;
};

export type ActivationStatus =
  | "PENDING_PAYMENT"
  | "PAYMENT_CONFIRMED"
  | "ACTIVATED"
  | "CANCELLED"
  | "EXPIRED"
  | "FAILED";

export type ActivationStatusResponse = {
  activation_id: string;
  status: ActivationStatus;
  cardano_tx_hash: string | null;
  expires_at: number;
  fail_reason: string | null;
};

export type ActivationEventData = {
  status: ActivationStatus;
  tx_hash?: string;
  reason?: string;
};

export type ActivationSubmitTxResponse = {
  activation_id: string;
  cardano_tx_hash: string;
};

export class ActivationModule {
  private readonly fetch: ReturnType<typeof createFetcher>;

  constructor(
    private readonly baseUrl: string,
    private readonly sseBaseUrl: string,
    private readonly _getSessionToken: () => string | null,
  ) {
    this.fetch = createFetcher(baseUrl);
  }

  /**
   * Initiate the activation package purchase. Server:
   *   1. Matches an available Genie
   *   2. Generates VietQR payment URL
   *   3. Opens a ProofChat session between user and Genie
   *
   * @param walletAddress  user's Bech32 Shelley address (where LAMP+ADA arrive)
   */
  async initiate(walletAddress: string): Promise<ActivationSession> {
    const token = this._getSessionToken();
    if (!token) throw new Error("Not authenticated");
    return this.fetch<ActivationSession>("/activation/initiate", {
      method: "POST",
      body: JSON.stringify({ wallet_address: walletAddress }),
      bearerToken: token,
    } as FetchOptions);
  }

  /**
   * Poll the activation status (fallback if SSE drops).
   */
  async getStatus(activationId: string): Promise<ActivationStatusResponse> {
    return this.fetch<ActivationStatusResponse>(`/activation/${activationId}/status`);
  }

  /**
   * Subscribe to lifecycle events via SSE. The stream emits events of types:
   *   - "payment_confirmed"
   *   - "activated"  (terminal — close stream after)
   *   - "failed"
   *   - "expired"
   *   - "cancelled"
   */
  openEventStream(
    activationId: string,
    handlers: SseHandlers<ActivationEventData>,
    sseOpts?: Partial<SseOptions>,
  ): ResilientSSE<ActivationEventData> {
    return new ResilientSSE<ActivationEventData>(
      {
        url: `/activation/${activationId}/events`,
        sseBaseUrl: this.sseBaseUrl,
        ...sseOpts,
      },
      handlers,
    );
  }

  /**
   * Cancel a pending activation (only allowed before payment).
   */
  async cancel(activationId: string): Promise<void> {
    const token = this._getSessionToken();
    if (!token) throw new Error("Not authenticated");
    await this.fetch<void>(`/activation/${activationId}/cancel`, {
      method: "POST",
      bearerToken: token,
    } as FetchOptions);
  }

  /**
   * Testnet only — admin token confirms payment without going through gateway.
   * Production: payment webhook calls this with HMAC-verified signature.
   *
   * NOTE: body intentionally empty. BE skips paymentReference validation when
   * null (admin token path) — only enforces match when a real payment gateway
   * webhook sends the reference. Sending a fake "MOCK-..." string would
   * mismatch BE's generated `PK<8hex>+<6hex>` and 4xx the request.
   */
  async mockConfirmPayment(activationId: string, adminToken: string): Promise<void> {
    await this.fetch<void>(`/activation/${activationId}/confirm-payment`, {
      method: "POST",
      headers: { "X-Admin-Token": adminToken },
      body: JSON.stringify({}),
    } as FetchOptions);
  }

  /**
   * Genie-only — submit Cardano-signed CBOR tx after user paid 200k off-chain.
   * Server submits to chain and resolves activation when confirmed.
   *
   * @param activationId   uuid from initiate response
   * @param signedTxCbor   hex-encoded CBOR (Genie's mobile signed with FEE_WALLET)
   */
  async submitTx(
    activationId: string,
    signedTxCbor: string,
  ): Promise<ActivationSubmitTxResponse> {
    const token = this._getSessionToken();
    if (!token) throw new Error("Not authenticated");
    return this.fetch<ActivationSubmitTxResponse>(
      `/activation/${activationId}/submit-tx`,
      {
        method: "POST",
        body: JSON.stringify({ signed_tx_cbor: signedTxCbor }),
        bearerToken: token,
      } as FetchOptions,
    );
  }
}
