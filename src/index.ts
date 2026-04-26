/**
 * @phoenixkey/sdk
 *
 * Identity & auth SDK for the MagicLamp ecosystem.
 * Docs: https://docs.phoenixkey.me
 * API:  https://api.phoenixkey.me/docs
 */

// Main client
export { PhoenixKeyClient } from "./client";

// Auth module (accessible via client.auth — re-exported for typing)
export { AuthModule } from "./auth";

// SSE (accessible via client.auth.openStream — re-exported for typing)
export { ResilientSSE } from "./sse";
export type { SseOptions } from "./sse";

// Session utilities (accessible via client.session)
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

// All types
export type {
  PhoenixKeyConfig,
  LoginSessionInit,
  LoginSessionStatus,
  SessionMeta,
  LinkedDevice,
  SseEvent,
  SseHandlers,
} from "./types";

// Error class — use instanceof for branching
export { PhoenixKeyError } from "./types";