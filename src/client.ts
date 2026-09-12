/**
 * PhoenixKey SDK — Main Client
 *
 * @example
 * ```ts
 * import { PhoenixKeyClient } from "@phoenixkeydid/phoenixkey-sdk";
 *
 * export const phoenix = new PhoenixKeyClient({
 *   appId:   "orilife-web-v1",
 *   appName: "OriLife",
 *   domain:  "orilife.com",
 *   environment: "mainnet",
 * });
 * ```
 */

import { PhoenixKeyConfig } from "./types";
import { AuthModule } from "./auth";
import { SignRequestModule } from "./signRequest";
import { IdentityModule } from "./identity";
import { AssetModule } from "./asset";
import { ActivityModule } from "./activity";
import { SeedModule } from "./seed";
import { FeesModule } from "./fees";
import { NetworkModule } from "./network";
import { SupportModule } from "./support";
import { WalletModule } from "./wallet";
import { WakemeModule } from "./wakeme";
import { DeviceModule } from "./device";
import { GuardianModule } from "./guardian";
import { OrgModule } from "./org";
import { PoolModule } from "./pool";
import { ResolverModule } from "./resolver";
import * as session from "./session";

/**
 * `client.session.*` — same shape as the free `session` functions, minus
 * `appId`: each instance's calls are pre-scoped to its own `config.appId`
 * (see constructor), so two clients sharing a browser origin never read or
 * clear each other's localStorage keys.
 *
 * Return types are read off the source functions so this can't drift from
 * `session.ts`, and `_boundSessionIsComplete` below fails the build if a new
 * export is added there and not surfaced here.
 */
type BoundSession = {
  getSessionToken(): ReturnType<typeof session.getSessionToken>;
  setSession(token: string, userDid?: string): void;
  clearSession(): void;
  getSessionMeta(): ReturnType<typeof session.getSessionMeta>;
  isLoggedIn(): boolean;
  getLinkedDevice(): ReturnType<typeof session.getLinkedDevice>;
  setLinkedDevice(token: string): void;
  clearLinkedDevice(): void;
  hasLinkedDevice(): boolean;
  clearAll(): void;
};

// `purgeLegacy` is deliberately absent from the bound surface: it deletes the
// pre-scoping keys, which belong to no app in particular, so binding it to one
// instance's appId would misdescribe what it does. The constructor calls it.
type UnboundSessionExports = Exclude<
  keyof typeof session,
  keyof BoundSession | "purgeLegacy"
>;
const _boundSessionIsComplete: [UnboundSessionExports] extends [never]
  ? true
  : never = true;
void _boundSessionIsComplete;

export class PhoenixKeyClient {
  /** QR-pairing login + linked-device flow (spec §6). */
  readonly auth: AuthModule;
  /** Web ↔ mobile sign request relay (spec §7). */
  readonly signRequest: SignRequestModule;
  /** DID resolve, pubkey lookup, health snapshot. */
  readonly identity: IdentityModule;
  /** Đúc AssetDID cho tài sản vật lý (farm/plot/tree/... — OriLifeTrace). */
  readonly asset: AssetModule;
  /** Activity logs với cursor pagination (spec §10). */
  readonly activity: ActivityModule;
  /** Seed Phrase export flow (spec §9.2). */
  readonly seed: SeedModule;
  /** Cardano fee estimate (MVP hardcode). */
  readonly fees: FeesModule;
  /** LampNet node map (spec §14.4 stub). */
  readonly network: NetworkModule;
  /** Get LAMP support session (spec §15.8 stub). */
  readonly support: SupportModule;
  /** Wallet balance + MAGIC accrual + claim (testnet release). */
  readonly wallet: WalletModule;
  /** Wakeme model A — vault GetLAMP, MAGIC yield, pot, GetMAGIC (spec §115). */
  readonly wakeme: WakemeModule;
  /** Vòng đời thiết bị tự-quản — xem/đặt tên/thu hồi (đòi phiên vai owner). */
  readonly devices: DeviceModule;
  /** Mạng lưới người bảo hộ khôi phục — thêm/gỡ/liệt kê (Social Recovery). */
  readonly guardians: GuardianModule;
  /** Vòng đời OrgDID + Grant uỷ quyền thao tác LAMP. */
  readonly org: OrgModule;
  /** Pool + uỷ quyền stake — CHỈ đọc, chuyển tiếp từ Blockfrost. */
  readonly pool: PoolModule;
  /** Tra DID theo chuẩn W3C (interop) + bộ khoá công khai JWKS. */
  readonly resolver: ResolverModule;

  /** localStorage helpers, scoped to this instance's `appId`. */
  readonly session: BoundSession;

  readonly config: Required<Omit<PhoenixKeyConfig, "apiKey">> & { apiKey?: string };

  constructor(config: PhoenixKeyConfig) {
    if (!config.appId) throw new Error("PhoenixKeyClient: appId required");
    if (!config.appName) throw new Error("PhoenixKeyClient: appName required");
    if (!config.domain) throw new Error("PhoenixKeyClient: domain required");

    // Every backend route lives under the `/api/v1` context path; the bare
    // origin returns 404. Callers passing their own apiBaseUrl must include it.
    const apiBaseUrl = config.apiBaseUrl ?? "https://api.phoenixkey.me/api/v1";

    this.config = {
      appId: config.appId,
      appName: config.appName,
      domain: config.domain,
      apiBaseUrl,
      sseBaseUrl: config.sseBaseUrl ?? apiBaseUrl,
      environment: config.environment ?? "mainnet",
      apiKey: config.apiKey,
    };

    // Drop the pre-scoping keys before anything reads storage. They hold a
    // still-live session token and linked-device token that no scoped code
    // path would ever clear, and they cannot be adopted into a scope: a
    // legacy blob carries no record of which app wrote it (see session.ts).
    session.purgeLegacy();

    // Every session.* call below is curried with this instance's appId, so
    // storage keys never collide with another PhoenixKeyClient on the same
    // origin (see scopedKey in session.ts).
    const appId = this.config.appId;
    const boundSession: BoundSession = {
      getSessionToken: () => session.getSessionToken(appId),
      setSession: (token, userDid) => session.setSession(token, userDid, appId),
      clearSession: () => session.clearSession(appId),
      getSessionMeta: () => session.getSessionMeta(appId),
      isLoggedIn: () => session.isLoggedIn(appId),
      getLinkedDevice: () => session.getLinkedDevice(appId),
      setLinkedDevice: (token) => session.setLinkedDevice(token, appId),
      clearLinkedDevice: () => session.clearLinkedDevice(appId),
      hasLinkedDevice: () => session.hasLinkedDevice(appId),
      clearAll: () => session.clearAll(appId),
    };
    this.session = boundSession;

    this.auth = new AuthModule(
      this.config.apiBaseUrl,
      this.config.sseBaseUrl,
      this.config.domain,
      boundSession.getLinkedDevice,
    );

    this.signRequest = new SignRequestModule(
      this.config.apiBaseUrl,
      this.config.sseBaseUrl,
      this.config.appId,
      this.config.domain,
      boundSession.getSessionToken,
    );

    this.identity = new IdentityModule(
      this.config.apiBaseUrl,
      boundSession.getSessionToken,
    );

    this.asset = new AssetModule(
      this.config.apiBaseUrl,
      boundSession.getSessionToken,
    );

    this.activity = new ActivityModule(
      this.config.apiBaseUrl,
      boundSession.getSessionToken,
    );

    this.seed = new SeedModule(
      this.config.apiBaseUrl,
      boundSession.getSessionToken,
    );

    this.fees = new FeesModule(this.config.apiBaseUrl);
    this.network = new NetworkModule(this.config.apiBaseUrl);
    this.support = new SupportModule(this.config.apiBaseUrl);
    this.wallet = new WalletModule(this.config.apiBaseUrl, boundSession.getSessionToken);
    this.wakeme = new WakemeModule(
      this.config.apiBaseUrl,
      this.config.sseBaseUrl,
      boundSession.getSessionToken,
    );
    this.devices = new DeviceModule(this.config.apiBaseUrl, boundSession.getSessionToken);
    this.guardians = new GuardianModule(
      this.config.apiBaseUrl,
      boundSession.getSessionToken,
    );
    this.org = new OrgModule(this.config.apiBaseUrl, boundSession.getSessionToken);
    // Hai module dưới chỉ đọc dữ liệu công khai — không nhận thẻ phiên, để
    // không có đường nào lỡ gắn thẻ vào một lượt gọi không cần thẻ.
    this.pool = new PoolModule(this.config.apiBaseUrl);
    this.resolver = new ResolverModule(this.config.apiBaseUrl);
  }

  /**
   * @deprecated Renamed to {@link wakeme}. Returns the very same instance, so
   * `phoenix.activation.*` keeps working for one release while callers move.
   */
  get activation(): WakemeModule {
    return this.wakeme;
  }

  /**
   * Returns true if a non-expired session_token exists in localStorage.
   * Use to guard routes before first API call.
   */
  isLoggedIn(): boolean {
    return this.session.isLoggedIn();
  }

  /** Clears this instance's PhoenixKey data (session + linked device). */
  logout(): void {
    this.session.clearAll();
  }
}
