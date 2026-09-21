/**
 * PhoenixKey SDK — Wakeme Module
 *
 * Wakeme is the single name for what used to be split across "Activation",
 * "GetLAMP" and "GetMAGIC". The server serves it under `/wakeme/*`; the older
 * `/activation/*` paths are aliases of the same handlers and are on their way
 * out (`WakemeController`, PhoenixKey-Database).
 *
 * Model A — two phases:
 *
 *   1. **Daily** (days 1…1001) — `buildGetLamp()` moves `D = min(1001,
 *      ⌊pot / 1_000_000⌋)` LAMP from the pot into the user's vault, locked.
 *      Locked LAMP generates MAGIC (the engine only *reads* the balance, it
 *      never burns LAMP). A day with no MAGIC spent returns 1 LAMP to the pot.
 *   2. **Epochy** (from day 1002) — each epoch (5 days) in which the user
 *      spends at least `min_magic_consume` MAGIC unlocks 5 LAMP into their
 *      wallet, owned and withdrawable. Idle epochs carry over; 1001 consecutive
 *      idle epochs forfeit the remainder back to the pot.
 *
 * Locked LAMP is a **right of use**, not a loan — no interest, no ownership, no
 * voting weight until it vests. Nothing is borrowed and nothing is owed.
 *
 * ## Endpoint status
 *
 * Every `/wakeme/*` route below is bound and its payload shape is settled, but
 * the service still answers `501 NOT_YET_IMPLEMENTED` until the vault validator
 * is deployed, the pot is funded and the Gen engine is wired
 * (`ActivationVaultServiceStub`). Build against these types now; the payloads
 * will not move under you.
 *
 * ## Transaction building
 *
 * The SDK does **not** build or parse redeemer CBOR. `buildGetLamp()` returns
 * an unsigned transaction the server assembled; the client signs it in the
 * Enclave and hands it back to `submitGetLamp()`. Model-A redeemer indices
 * (spend `Reclaim 0 · OwnEpoch 1 · ReclaimEpoch 2`; mint `GenesisVault 0 ·
 * CloseVault 1`) live in `rust_core` and the Aiken validators, not here.
 *
 * A fourth spend redeemer, `Redeem 3`, was listed here until 2026-09-21. It no
 * longer exists: the validator carries exactly the three above. Anything that
 * encoded index 3 would be rejected on-chain, and anything that told a user
 * their owned LAMP could be spent out was saying the opposite of what the
 * contract guarantees.
 */

import { createFetcher, FetchOptions } from "./fetcher";
import { ResilientSSE, SseOptions } from "./sse";
import { PhoenixKeyError, SseHandlers } from "./types";

// ─── Model A — GetLAMP into the vault ────────────────────────────────────────

export type WakemeBuildRequest = {
  /** Bech32 Shelley address that will hold the vault. */
  wallet_address: string;
  /** Optional `blake2b_256(did ‖ salt)` hex; the server derives one if absent. */
  did_commit?: string;
};

export type WakemeBuildResponse = {
  unsigned_tx_cbor: string;
  /**
   * **Every** key the transaction requires, in the order the builder added
   * them. GetLAMP needs **two**: `controller_pkh` then `device_pkh`.
   *
   * ⚠ Replaces the singular `required_signer_key_hash`, which carried only the
   * first of the two. Signing with one key produces a transaction the chain
   * rejects, and the rejection does not say which key is missing — nor can the
   * client infer it, since a DID may have several authorised device keys and
   * the server's preflight already picked one. The backend dropped the
   * singular field outright rather than keep a wrong name beside a right one
   * (Issue #282); an SDK type still promising it resolves to `undefined`.
   */
  required_signer_key_hashes: string[];
  vault_address: string;
  d_lamp: number;
  /** Smallest unit (oildrop) — JSON string, do not parse as a JS number. */
  d_oildrop: string;
  /** Pot total in LAMP — JSON string, do not parse as a JS number. */
  pot_balance_lamp: string;
  /**
   * The transaction's `validFrom` **slot** — a build-time bound on the
   * unsigned transaction, nothing more.
   *
   * ⚠ Not to be confused with {@link WakemeVaultStatus.vest_start_ms}, which
   * is the vault clock's zero point. They differ in **both** unit and origin
   * (slots vs POSIX milliseconds; ~720 slot ↔ 720000 ms), so neither converts
   * into the other by scaling. The near-identical names are the wire contract
   * the backend already serves (`vestStartSlot` → `vest_start_slot`), so they
   * are not renamed here — a one-sided rename would break every caller.
   */
  vest_start_slot: number;
  phase1_days: number;
  ttl_slot: number;
};

export type WakemeSubmitResponse = {
  cardano_tx_hash: string;
  vault_address: string;
  status: string;
};

/** Anti-wash gate — spending real MAGIC through the Registry is what counts. */
export type WakemeActivityGate = {
  used_this_period: boolean | null;
  grace_active: boolean | null;
  grace_days_left: number | null;
  epoch_used: boolean | null;
  at_risk_lamp: number | null;
  min_magic_consume: string | null;
  warning: string | null;
  note: string | null;
};

/**
 * Vault dashboard payload.
 *
 * ## ⚠ Two LAMP units live in this one object, and the field names do not
 * separate them
 *
 * `conditional_lamp`, `owned_lamp`, `reclaimed_to_pot_lamp` and `d_unit` are
 * all in **oildrop** (1 LAMP = 10⁶ oildrop) — they mirror the on-chain datum
 * `WakemeVaultDatum`, which counts in oildrop throughout. `initial_dlamp` is
 * in **whole LAMP** (≤ 1001).
 *
 * So the `_lamp` suffix here means "this is a LAMP quantity", *not* "this is
 * denominated in whole LAMP". Formatting an oildrop figure as whole LAMP (or
 * the reverse) is off by a factor of a million, raises no error, and still
 * looks like a plausible number. The names are kept as-is because they are the
 * wire contract the backend already serves — renaming them in the SDK alone
 * would break every caller. Read the unit off this doc, never off the suffix.
 *
 * @see WakemeBuildResponse.d_oildrop — same unit, honest name.
 */
export type WakemeVaultStatus = {
  did: string;
  vault_address: string;
  /** 1 = Daily, 2 = Epochy. */
  phase: 1 | 2;
  days_elapsed: number;
  phase1_days_total: number;
  days_to_phase2: number;
  /**
   * Whole LAMP (capped at 1001), **not** oildrop — the `D` this vault was
   * opened with.
   *
   * ⚠ The wire key is `initial_dlamp` — one word, no underscore between `d`
   * and `lamp`. Jackson's `SnakeCaseStrategy` does not insert a separator
   * between two consecutive capitals, so the backend field `initialDLamp`
   * serialises to `initial_dlamp`, never `initial_d_lamp`. Reading the
   * underscored spelling returns `undefined` and throws nothing.
   */
  initial_dlamp: number;
  /**
   * LAMP still locked — generates MAGIC, not yet owned by the user.
   *
   * **Unit: OILDROP** (1 LAMP = 10⁶ oildrop), despite the `_lamp` suffix.
   * See the unit note above this type.
   */
  conditional_lamp: number;
  /**
   * LAMP owned outright — together with `conditional_lamp` decides how much
   * MAGIC the vault generates.
   *
   * **Only ever grows**, via the `OwnEpoch` redeemer. It is never forfeited and
   * no redeemer can spend it: the `Redeem` path this doc used to name was
   * removed from the validator, so there is no longer any transaction that
   * takes owned LAMP back out. Treat a drop in this number as a bug on our
   * side, not as something the user did.
   *
   * **Unit: OILDROP**, despite the `_lamp` suffix.
   */
  owned_lamp: number;
  /**
   * Nightly rate `D = WakemeUsageRight / 1001` — fixed per vault from genesis,
   * invariant across every redeemer.
   *
   * **Unit: OILDROP.** No suffix says so; the sibling field `d_oildrop` on
   * {@link WakemeBuildResponse} carries the same unit under an honest name.
   */
  d_unit: number;
  /**
   * LAMP returned to the pot (daily anti-idle + Epochy forfeit).
   *
   * **Unit: OILDROP**, despite the `_lamp` suffix. On-chain this is the datum
   * field `reclaimed_to_pot` — the `_lamp` tail is added by the wire DTO only.
   */
  reclaimed_to_pot_lamp: number;
  /**
   * POSIX **milliseconds** at GetLAMP — the day/epoch clock's zero point.
   * NOT a slot (Issue #256 renamed this from `vest_start_slot`).
   */
  vest_start_ms: number;
  magic_generated_total: string | null;
  magic_balance_current: string | null;
  last_tick_day: number | null;
  last_tick_epoch: number | null;
  p2_epoch: number | null;
  activity_gate: WakemeActivityGate;
};

export type WakemeVaultMagic = {
  did: string;
  phase: 1 | 2;
  gen_basis_lamp: number;
  magic_per_epoch_est: string;
  magic_generated_total: string;
  last_fire_epoch: number;
  next_fire_epoch: number;
  note_readonly: string;
  note_granularity: string;
};

export type WakemePotStatus = {
  /** JSON string — the pot can exceed 2⁵³. */
  pot_balance_lamp: string;
  /**
   * D a new user would receive right now — whole LAMP, capped at 1001.
   *
   * ⚠ The wire key is `current_dlamp` — one word, no underscore between `d`
   * and `lamp`, for the same Jackson reason as
   * {@link WakemeVaultStatus.initial_dlamp}. This is the "how much LAMP will I
   * get" number a whole screen is built around, so reading it under the
   * underscored spelling yields `undefined` with no error anywhere.
   */
  current_dlamp: number;
  d_cap: number;
  scale: number;
  saturated: boolean;
};

export type WakemeGenEntry = {
  did: string;
  phase: 1 | 2;
  gen_basis_lamp: number;
  sdk_link: string;
  note_readonly: string;
};

// ─── GetMAGIC — buy CARP with fiat through GreenBack ─────────────────────────

export type WakemeMagicQuoteRequest = {
  /** ISO-4217, e.g. "VND". */
  fiat_currency: string;
  /** Smallest unit. Send exactly one of `fiat_amount` / `carp_amount`. */
  fiat_amount?: number;
  carp_amount?: number;
};

export type WakemeMagicQuote = {
  quote_id: string;
  fiat_currency: string;
  fiat_amount: number;
  carp_amount: number;
  rate: string;
  fee_breakdown: { fx_buffer: number; network: number };
  expires_at: number;
};

export type WakemeMagicCheckout = {
  order_id: string;
  payment_url: string;
  carp_amount: number;
  status: string;
  expires_at: number;
};

export type WakemeMagicOrderStatus = {
  order_id: string;
  status: "PENDING_PAYMENT" | "PAID" | "CARP_DELIVERED" | "FAILED" | "EXPIRED";
  carp_amount: number;
  cardano_tx_hash: string | null;
  fail_reason: string | null;
};

// ─── Legacy — the VND / Genie activation package ─────────────────────────────

/**
 * @deprecated The 200,000₫ → 1001 LAMP + 10 ADA package bought through a Genie
 * agent is retired; `ActivationController` on the backend carries the same
 * notice. Wakeme model A replaces it — write nothing new against these types.
 */
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

/** @deprecated Part of the retired VND / Genie flow. */
export type ActivationStatus =
  | "PENDING_PAYMENT"
  | "PAYMENT_CONFIRMED"
  | "ACTIVATED"
  | "CANCELLED"
  | "EXPIRED"
  | "FAILED";

/** @deprecated Part of the retired VND / Genie flow. */
export type ActivationStatusResponse = {
  activation_id: string;
  status: ActivationStatus;
  cardano_tx_hash: string | null;
  expires_at: number;
  fail_reason: string | null;
};

/** @deprecated Part of the retired VND / Genie flow. */
export type ActivationEventData = {
  status: ActivationStatus;
  tx_hash?: string;
  reason?: string;
};

/** @deprecated Part of the retired VND / Genie flow. */
export type ActivationSubmitTxResponse = {
  cardano_tx_hash: string;
  /** BE returns "SUBMITTED" or "ACTIVATED" depending on confirmation latency. */
  status: ActivationStatus;
};

export class WakemeModule {
  private readonly fetch: ReturnType<typeof createFetcher>;

  constructor(
    private readonly baseUrl: string,
    private readonly sseBaseUrl: string,
    private readonly _getSessionToken: () => string | null,
  ) {
    this.fetch = createFetcher(baseUrl);
  }

  private requireToken(): string {
    const token = this._getSessionToken();
    if (!token) throw new Error("Not authenticated");
    return token;
  }

  // ── Model A — vault ────────────────────────────────────────────────────────

  /**
   * Step 1 — ask the server for an unsigned transaction that moves `D` LAMP
   * from the pot into a vault at `wallet_address` and locks it.
   *
   * One DID gets one vault; a second call is guarded server-side. Sign the
   * returned CBOR in the Enclave, then pass it to {@link submitGetLamp}.
   */
  async buildGetLamp(req: WakemeBuildRequest): Promise<WakemeBuildResponse> {
    return this.fetch<WakemeBuildResponse>("/wakeme/build", {
      method: "POST",
      body: JSON.stringify(req),
      bearerToken: this.requireToken(),
    } as FetchOptions);
  }

  /** Step 2 — hand back the Enclave-signed CBOR for submission to the chain. */
  async submitGetLamp(signedTxCbor: string): Promise<WakemeSubmitResponse> {
    return this.fetch<WakemeSubmitResponse>("/wakeme/submit", {
      method: "POST",
      body: JSON.stringify({ signed_tx_cbor: signedTxCbor }),
      bearerToken: this.requireToken(),
    } as FetchOptions);
  }

  /** Vault dashboard — phase, locked LAMP, vesting, activity gate. Public read. */
  async getVaultStatus(did: string): Promise<WakemeVaultStatus> {
    return this.fetch<WakemeVaultStatus>(`/wakeme/vault/${encodeURIComponent(did)}`);
  }

  /** Daily MAGIC yield. The engine reads the balance; it never spends LAMP. */
  async getVaultMagic(did: string): Promise<WakemeVaultMagic> {
    return this.fetch<WakemeVaultMagic>(
      `/wakeme/vault/${encodeURIComponent(did)}/magic`,
    );
  }

  /** Pot health — how much a new user would receive right now. */
  async getPotStatus(): Promise<WakemePotStatus> {
    return this.fetch<WakemePotStatus>("/wakeme/pot");
  }

  /** Boundary between the Gen engine and the MAGIC SDK. Informational. */
  async getGenEntry(did: string): Promise<WakemeGenEntry> {
    return this.fetch<WakemeGenEntry>(
      `/wakeme/gen-entry?did=${encodeURIComponent(did)}`,
    );
  }

  // ── GetMAGIC — fiat → CARP ─────────────────────────────────────────────────

  async quoteMagic(req: WakemeMagicQuoteRequest): Promise<WakemeMagicQuote> {
    return this.fetch<WakemeMagicQuote>("/wakeme/getmagic/quote", {
      method: "POST",
      body: JSON.stringify(req),
      bearerToken: this.requireToken(),
    } as FetchOptions);
  }

  async checkoutMagic(
    quoteId: string,
    paymentMethod: string,
  ): Promise<WakemeMagicCheckout> {
    return this.fetch<WakemeMagicCheckout>("/wakeme/getmagic/checkout", {
      method: "POST",
      body: JSON.stringify({ quote_id: quoteId, payment_method: paymentMethod }),
      bearerToken: this.requireToken(),
    } as FetchOptions);
  }

  async getMagicOrder(orderId: string): Promise<WakemeMagicOrderStatus> {
    return this.fetch<WakemeMagicOrderStatus>(
      `/wakeme/getmagic/${encodeURIComponent(orderId)}`,
      { bearerToken: this.requireToken() } as FetchOptions,
    );
  }

  // ── Legacy VND / Genie flow ────────────────────────────────────────────────
  //
  // Kept so existing integrations keep compiling. These still call
  // `/activation/*` and have no `/wakeme/*` counterpart — the flow was retired,
  // not renamed.
  //
  // 🔴 ĐO 2026-09-08 — sáu phương thức dưới đây KHÔNG CÒN máy chủ nào phục vụ.
  // Không phải "sắp bỏ": bỏ rồi. `PhoenixKey-Database` gỡ luồng VND-Genie ngày
  // 2026-09-03 (`docs/VND-GENIE-REMOVAL.md`), và `ActivationVaultController`
  // hôm nay chỉ còn bind `/getlamp/build` · `/getlamp/submit` · `/vault/{did}`
  // · `/vault/{did}/magic` · `/getmagic/quote` · `/getmagic/checkout`
  // · `/getmagic/{orderId}` · `/gen-entry` · `/pot`. Sáu đường mà khối này gọi
  // — `/activation/initiate`, `/{id}/status`, `/{id}/events`, `/{id}/cancel`,
  // `/{id}/confirm-payment`, `/{id}/submit-tx` — không khớp handler nào ⇒ 404.
  //
  // CHỐT (#9) — sáu phương thức này nay NÉM NGAY, không đi mạng.
  //
  // Chú thích cũ hoãn quyết định này với lý do "bên nào còn ghim máy chủ bản cũ
  // thì đổi là phá họ". Em cân lại và lý do đó không đứng được:
  //
  //  • Với máy chủ HÔM NAY, người gọi ĐÃ nhận ngoại lệ rồi — `fetcher` ném
  //    `PhoenixKeyError{status: 404, code: "http_404", message: "Not Found"}`
  //    (fetcher.ts:170-190). Nên đây không phải "đang chạy được thì bị chặn".
  //    Đổi chỉ làm cùng một thất bại xảy ra sớm hơn, không tiêu một lượt đi
  //    mạng, và nói ĐÚNG nguyên nhân. Bốn trong sáu còn gọi `requireToken()`
  //    trước, nên bên không có session nhận "thiếu session" — một lời chẩn
  //    đoán sai về một luồng vốn đã không tồn tại.
  //  • Bên còn ghim máy chủ bản cũ thì ghim luôn SDK bản cũ. Đó đúng là việc
  //    ghim phiên bản dùng để làm. Giữ một đường 404 sống trong thư viện MỚI
  //    để phục vụ một máy chủ CŨ là trả giá bằng mọi người còn lại.
  //
  // Phương thức được GIỮ (không xoá) nên mã người dùng vẫn biên dịch — đó là ý
  // của "giữ alias một vòng release" trong #9. Thứ đổi là chúng thất bại sớm và
  // nói rõ, thay vì thất bại muộn và nói sai. Vòng release sau thì xoá.
  private static retired(method: string, replacement: string): PhoenixKeyError {
    return new PhoenixKeyError({
      // 0 = KHÔNG có phản hồi HTTP nào. Cố ý không dùng 410: không máy chủ nào
      // nói "Gone" ở đây — lỗi này chưa từng rời khỏi máy khách, và dựng ra một
      // mã trạng thái mà không ai gửi là để người đọc log đi tìm một phản hồi
      // không tồn tại.
      status: 0,
      code: "flow_retired",
      // defaultUserMessageKey(0) trả "errors.network" — SAI ở đây, đây không
      // phải sự cố mạng. Truyền khoá riêng.
      userMessageKey: "errors.flow_retired",
      message:
        `WakemeModule.${method}() thuộc luồng VND/Genie đã được gỡ khỏi ` +
        `PhoenixKey-Database ngày 2026-09-03 (docs/VND-GENIE-REMOVAL.md). ` +
        `Không còn handler nào phục vụ đường này ⇒ gọi tiếp chỉ nhận 404. ` +
        `Dùng ${replacement}.`,
      details: { retiredOn: "2026-09-03", replacement },
    });
  }

  /**
   * @deprecated Retired flow. Use {@link buildGetLamp}.
   *
   * Initiate the 200,000₫ activation package purchase through a Genie agent.
   */
  async initiate(_walletAddress: string): Promise<ActivationSession> {
    throw WakemeModule.retired("initiate", "buildGetLamp()");
  }

  /** @deprecated Retired flow. Use {@link getVaultStatus}. */
  async getStatus(_activationId: string): Promise<ActivationStatusResponse> {
    throw WakemeModule.retired("getStatus", "getVaultStatus()");
  }

  /** @deprecated Retired flow. */
  openEventStream(
    _activationId: string,
    _handlers: SseHandlers<ActivationEventData>,
    _sseOpts?: Partial<SseOptions>,
  ): ResilientSSE<ActivationEventData> {
    // Ném ĐỒNG BỘ, không trả về một ResilientSSE rồi để nó tự thất bại: một SSE
    // trỏ vào đường 404 sẽ THỬ LẠI theo backoff, tức biến một tính năng đã bỏ
    // thành một vòng lặp gọi mạng vô hạn im lặng.
    throw WakemeModule.retired("openEventStream", "getVaultStatus()");
  }

  /** @deprecated Retired flow. */
  async cancel(_activationId: string): Promise<void> {
    throw WakemeModule.retired("cancel", "— không có đường thay thế, luồng đã bỏ");
  }

  /**
   * @deprecated Retired flow.
   *
   * Testnet only — an admin token confirms payment without going through the
   * gateway. The body is intentionally empty: the backend's match check is
   * null-gated, so a fake reference would mismatch its generated
   * `PK<8hex>+<6hex>` and 4xx the request.
   */
  async mockConfirmPayment(_activationId: string, _adminToken: string): Promise<void> {
    throw WakemeModule.retired(
      "mockConfirmPayment",
      "— không có đường thay thế, luồng đã bỏ",
    );
  }

  /** @deprecated Retired flow. Use {@link submitGetLamp}. */
  async submitTx(
    _activationId: string,
    _signedTxCbor: string,
  ): Promise<ActivationSubmitTxResponse> {
    throw WakemeModule.retired("submitTx", "submitGetLamp()");
  }
}

/**
 * @deprecated Renamed to {@link WakemeModule}. The alias stays for one release
 * so nothing breaks mid-upgrade — it is the same class, not a wrapper.
 */
export const ActivationModule = WakemeModule;
/** @deprecated Renamed to {@link WakemeModule}. */
export type ActivationModule = WakemeModule;
