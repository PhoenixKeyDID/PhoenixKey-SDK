import { PhoenixKeyClient } from "../src/client";
import * as session from "../src/session";

/**
 * `localStorage` is per-ORIGIN, not per-app. Two apps using this SDK on one
 * domain — two sub-apps of a portal, two environments on a staging host —
 * used to write the same three fixed keys, so app A would read app B's ticket
 * and act under B's identity with nothing reporting an error.
 *
 * The fix suffixes every key with `appId`. These tests pin the property that
 * matters (A never observes B's writes), not the exact key spelling — except
 * where the spelling IS the contract: legacy unsuffixed keys must be gone.
 */

const SESSION_KEY = "phoenix_session_token";
const SESSION_META_KEY = "phoenix_session_meta";
const LINKED_DEVICE_KEY = "phoenix_linked_device";

/** Minimal localStorage — the test env is `node`, there is no jsdom here. */
function installBrowser(): Map<string, string> {
  const store = new Map<string, string>();
  const localStorage = {
    getItem: (k: string) => (store.has(k) ? store.get(k)! : null),
    setItem: (k: string, v: string) => void store.set(k, String(v)),
    removeItem: (k: string) => void store.delete(k),
    clear: () => store.clear(),
  };
  Object.assign(globalThis as Record<string, unknown>, {
    window: { localStorage },
    localStorage,
  });
  return store;
}

function uninstallBrowser(): void {
  delete (globalThis as Record<string, unknown>).window;
  delete (globalThis as Record<string, unknown>).localStorage;
}

function clientFor(appId: string): PhoenixKeyClient {
  return new PhoenixKeyClient({
    appId,
    appName: appId,
    domain: "portal.example",
  });
}

/** An opaque token — `parseJwtExp` falls back to the default TTL for it. */
const TOKEN_A = "token-for-app-a";
const TOKEN_B = "token-for-app-b";

describe("session keys are scoped per appId", () => {
  let store: Map<string, string>;

  beforeEach(() => {
    store = installBrowser();
  });

  afterEach(() => {
    uninstallBrowser();
  });

  it("two clients on one origin do not read each other's session", () => {
    const a = clientFor("app-a");
    const b = clientFor("app-b");

    a.session.setSession(TOKEN_A, "did:phoenix:aaa");
    b.session.setSession(TOKEN_B, "did:phoenix:bbb");

    expect(a.session.getSessionToken()).toBe(TOKEN_A);
    expect(b.session.getSessionToken()).toBe(TOKEN_B);
    expect(a.session.getSessionMeta()?.userDid).toBe("did:phoenix:aaa");
    expect(b.session.getSessionMeta()?.userDid).toBe("did:phoenix:bbb");
  });

  it("the pre-fix failure is gone: B logging in does not re-identify A", () => {
    const a = clientFor("app-a");
    a.session.setSession(TOKEN_A, "did:phoenix:aaa");

    // User walks over to the neighbouring app and signs in as someone else.
    clientFor("app-b").session.setSession(TOKEN_B, "did:phoenix:bbb");

    // ...then comes back. A must still be A.
    expect(a.session.getSessionToken()).toBe(TOKEN_A);
    expect(a.session.getSessionMeta()?.userDid).toBe("did:phoenix:aaa");
  });

  it("logout on one app leaves the other logged in", () => {
    const a = clientFor("app-a");
    const b = clientFor("app-b");
    a.session.setSession(TOKEN_A);
    b.session.setSession(TOKEN_B);
    a.session.setLinkedDevice(TOKEN_A);
    b.session.setLinkedDevice(TOKEN_B);

    a.logout();

    expect(a.isLoggedIn()).toBe(false);
    expect(a.session.hasLinkedDevice()).toBe(false);
    expect(b.isLoggedIn()).toBe(true);
    expect(b.session.getLinkedDevice()?.token).toBe(TOKEN_B);
  });

  it("linked-device tokens are per-app — B's device never skips A's QR", () => {
    const a = clientFor("app-a");
    clientFor("app-b").session.setLinkedDevice(TOKEN_B);

    expect(a.session.hasLinkedDevice()).toBe(false);
    expect(a.session.getLinkedDevice()).toBeNull();
  });

  it("an expired session in one scope clears only that scope", () => {
    const a = clientFor("app-a");
    const b = clientFor("app-b");
    a.session.setSession(TOKEN_A);
    b.session.setSession(TOKEN_B);

    // Age app A's session past its TTL without touching app B's.
    const metaKey = `${SESSION_META_KEY}:app-a`;
    store.set(metaKey, JSON.stringify({ expiresAt: Date.now() - 1 }));

    expect(a.session.getSessionToken()).toBeNull();
    expect(b.session.getSessionToken()).toBe(TOKEN_B);
  });

  it("calling session.* directly without an appId lands in its own bucket", () => {
    const a = clientFor("app-a");
    a.session.setSession(TOKEN_A);

    session.setSession(TOKEN_B);

    // The unscoped caller gets its own storage, and — the point of the
    // `DEFAULT_SCOPE` bucket — it does NOT write the bare legacy key.
    expect(session.getSessionToken()).toBe(TOKEN_B);
    expect(a.session.getSessionToken()).toBe(TOKEN_A);
    expect(store.has(SESSION_KEY)).toBe(false);
  });

  it("every write is SSR-safe and every read is null on the server", () => {
    uninstallBrowser();
    const a = clientFor("app-a");

    expect(() => a.session.setSession(TOKEN_A)).not.toThrow();
    expect(() => a.session.setLinkedDevice(TOKEN_A)).not.toThrow();
    expect(() => a.logout()).not.toThrow();
    expect(a.session.getSessionToken()).toBeNull();
    expect(a.session.getSessionMeta()).toBeNull();
    expect(a.session.getLinkedDevice()).toBeNull();
    expect(a.isLoggedIn()).toBe(false);
  });
});

describe("pre-scoping keys are deleted, never adopted", () => {
  let store: Map<string, string>;

  beforeEach(() => {
    store = installBrowser();
  });

  afterEach(() => {
    uninstallBrowser();
  });

  /** What an SDK version before scoping left behind on this origin. */
  function seedLegacy(): void {
    store.set(SESSION_KEY, "legacy-session-token");
    store.set(
      SESSION_META_KEY,
      JSON.stringify({ expiresAt: Date.now() + 3_600_000, userDid: "did:phoenix:old" }),
    );
    store.set(
      LINKED_DEVICE_KEY,
      JSON.stringify({ token: "legacy-linked-device", expiresAt: Date.now() + 3_600_000 }),
    );
  }

  it("constructing a client drops all three legacy keys", () => {
    seedLegacy();

    clientFor("app-a");

    expect(store.has(SESSION_KEY)).toBe(false);
    expect(store.has(SESSION_META_KEY)).toBe(false);
    expect(store.has(LINKED_DEVICE_KEY)).toBe(false);
  });

  it("the legacy session is NOT adopted — it belongs to no known app", () => {
    seedLegacy();

    const a = clientFor("app-a");

    // One re-login is the deliberate price. Silently adopting the blob would
    // hand whichever app boots first a session the other app may have left.
    expect(a.isLoggedIn()).toBe(false);
    expect(a.session.getSessionToken()).toBeNull();
    expect(a.session.getSessionMeta()).toBeNull();
    expect(a.session.hasLinkedDevice()).toBe(false);
  });

  it("the purge does not touch a scoped session that already exists", () => {
    const a = clientFor("app-a");
    a.session.setSession(TOKEN_A, "did:phoenix:aaa");
    seedLegacy();

    // A second client — a page that constructs one per route, say.
    clientFor("app-b");

    expect(a.session.getSessionToken()).toBe(TOKEN_A);
    expect(store.has(SESSION_KEY)).toBe(false);
  });

  it("purgeLegacy is idempotent and SSR-safe", () => {
    seedLegacy();
    session.purgeLegacy();
    expect(() => session.purgeLegacy()).not.toThrow();
    expect(store.size).toBe(0);

    uninstallBrowser();
    expect(() => session.purgeLegacy()).not.toThrow();
  });
});
