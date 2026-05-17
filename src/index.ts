/**
 * @phoenixkeydid/phoenixkey-sdk
 *
 * Identity & auth SDK for the MagicLamp / Aladin ecosystem.
 *
 * Docs: https://docs.phoenixkey.me
 * API:  https://api.phoenixkey.me/api/v1
 */

export { PhoenixKeyClient } from "./client";

// Modules (typing re-export — accessible via client.<module>)
export { AuthModule } from "./auth";
export { SignRequestModule } from "./signRequest";
export type { SignSseData } from "./signRequest";
export { IdentityModule } from "./identity";
export { ActivityModule } from "./activity";
export { SeedModule } from "./seed";
export { FeesModule } from "./fees";
export type { FeeType } from "./fees";
export { NetworkModule } from "./network";
export { SupportModule } from "./support";
export { WalletModule, PREPROD_SLOT_ORIGIN_MS, MAINNET_SLOT_ORIGIN_MS } from "./wallet";
export type { Balance, MagicClaimResult } from "./wallet";
export { ActivationModule } from "./activation";
export type {
  ActivationSession,
  ActivationStatus,
  ActivationStatusResponse,
  ActivationEventData,
  ActivationSubmitTxResponse,
} from "./activation";

// SSE primitive (advanced — for custom flows)
export { ResilientSSE } from "./sse";
export type { SseOptions } from "./sse";

// Session / linked-device storage
export {
  getSessionToken,
  setSession,
  clearSession,
  getSessionMeta,
  isLoggedIn,
  getLinkedDevice,
  setLinkedDevice,
  clearLinkedDevice,
  hasLinkedDevice,
  clearAll,
} from "./session";

// Types
export type {
  PhoenixKeyConfig,
  // Auth
  LoginSessionInit,
  LoginSessionStatus,
  QrPayload,
  // Sign Request
  SignIntent,
  SignRequestCreate,
  SignRequestPayload,
  SignedEventData,
  CancelledEventData,
  // Identity
  IdentityRegisterRequest,
  IdentityRegisterResponse,
  IdentityPubkey,
  IdentityStatus,
  IdentityHealth,
  W3CDIDDocument,
  // Activity
  ActivityLogItem,
  ActivityLogPage,
  ActivityLogQuery,
  // Misc
  FeeEstimate,
  LampNetNode,
  LampNetNodes,
  SupportSession,
  // SSE
  SseEvent,
  SseHandlers,
  // Storage
  SessionMeta,
  LinkedDevice,
} from "./types";

// Errors
export { PhoenixKeyError } from "./types";

// Fetcher (advanced — typically not needed)
export { ERROR_CODE_MAP } from "./fetcher";
