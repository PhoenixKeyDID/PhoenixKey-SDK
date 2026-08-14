import { PhoenixKeyVerifier } from "../src/verifier";

const BASE = "https://api.example.test/api/v1";
const PUBKEY_A = "04".padEnd(130, "a");
const PUBKEY_B = "04".padEnd(130, "b");

afterEach(() => {
  jest.restoreAllMocks();
});

type KeyBody = { public_key_hex: string; key_id?: string; status?: string };

/** Serve a queue of pubkey responses; the last one repeats. */
function mockPubkey(...bodies: KeyBody[]) {
  let i = 0;
  return jest.spyOn(globalThis, "fetch").mockImplementation((async () => {
    const body = bodies[Math.min(i, bodies.length - 1)];
    i += 1;
    return new Response(JSON.stringify({ code: 1000, message: "ok", result: body }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }) as typeof fetch);
}

describe("resolveKey — a key the response cannot identify is not cached", () => {
  it("refetches every time when the backend sends no key_id", async () => {
    // Today's backend: only public_key_hex + key_role. Nothing to notice a
    // rotation by, so holding the key would keep a revoked key alive.
    const f = mockPubkey({ public_key_hex: PUBKEY_A });
    const v = new PhoenixKeyVerifier({ phoenixkeyApiUrl: BASE });

    await v.resolvePubkey("did:phoenix:aaaaaaaiusdea:ab");
    await v.resolvePubkey("did:phoenix:aaaaaaaiusdea:ab");
    await v.resolvePubkey("did:phoenix:aaaaaaaiusdea:ab");

    expect(f).toHaveBeenCalledTimes(3);
  });

  it("sees a rotation immediately — this is the #11 window, closed", async () => {
    mockPubkey({ public_key_hex: PUBKEY_A }, { public_key_hex: PUBKEY_B });
    const v = new PhoenixKeyVerifier({ phoenixkeyApiUrl: BASE });

    await expect(v.resolvePubkey("did:phoenix:x:y")).resolves.toBe(PUBKEY_A);
    // Victim rotates here. No TTL to wait out.
    await expect(v.resolvePubkey("did:phoenix:x:y")).resolves.toBe(PUBKEY_B);
  });

  it("caches anyway when the integrator opts in explicitly", async () => {
    const f = mockPubkey({ public_key_hex: PUBKEY_A }, { public_key_hex: PUBKEY_B });
    const v = new PhoenixKeyVerifier({
      phoenixkeyApiUrl: BASE,
      allowUnidentifiedKeyCache: true,
    });

    await expect(v.resolvePubkey("did:phoenix:x:y")).resolves.toBe(PUBKEY_A);
    await expect(v.resolvePubkey("did:phoenix:x:y")).resolves.toBe(PUBKEY_A);
    expect(f).toHaveBeenCalledTimes(1);
  });
});

describe("resolveKey — an identified key is cached", () => {
  it("hits the network once while key_id is present", async () => {
    const f = mockPubkey({ public_key_hex: PUBKEY_A, key_id: "k-1", status: "active" });
    const v = new PhoenixKeyVerifier({ phoenixkeyApiUrl: BASE });

    await v.resolvePubkey("did:phoenix:x:y");
    await v.resolvePubkey("did:phoenix:x:y");
    expect(f).toHaveBeenCalledTimes(1);
  });

  it("exposes keyId and status through resolveKey", async () => {
    mockPubkey({ public_key_hex: PUBKEY_A, key_id: "k-1", status: "active" });
    const v = new PhoenixKeyVerifier({ phoenixkeyApiUrl: BASE });

    await expect(v.resolveKey("did:phoenix:x:y")).resolves.toEqual({
      publicKeyHex: PUBKEY_A,
      keyId: "k-1",
      status: "active",
    });
  });

  it("invalidate() drops the entry and forces a refetch", async () => {
    const f = mockPubkey(
      { public_key_hex: PUBKEY_A, key_id: "k-1", status: "active" },
      { public_key_hex: PUBKEY_B, key_id: "k-2", status: "active" },
    );
    const v = new PhoenixKeyVerifier({ phoenixkeyApiUrl: BASE });

    await expect(v.resolvePubkey("did:phoenix:x:y")).resolves.toBe(PUBKEY_A);
    expect(v.invalidate("did:phoenix:x:y")).toBe(true);
    expect(v.invalidate("did:phoenix:x:y")).toBe(false);
    await expect(v.resolvePubkey("did:phoenix:x:y")).resolves.toBe(PUBKEY_B);
    expect(f).toHaveBeenCalledTimes(2);
  });

  it("clearCache() drops everything", async () => {
    const f = mockPubkey({ public_key_hex: PUBKEY_A, key_id: "k-1", status: "active" });
    const v = new PhoenixKeyVerifier({ phoenixkeyApiUrl: BASE });

    await v.resolvePubkey("did:phoenix:x:y");
    v.clearCache();
    await v.resolvePubkey("did:phoenix:x:y");
    expect(f).toHaveBeenCalledTimes(2);
  });

  it("stops honouring the entry once cacheTtlMs has elapsed", async () => {
    const f = mockPubkey(
      { public_key_hex: PUBKEY_A, key_id: "k-1", status: "active" },
      { public_key_hex: PUBKEY_B, key_id: "k-2", status: "active" },
    );
    const v = new PhoenixKeyVerifier({ phoenixkeyApiUrl: BASE, cacheTtlMs: 1000 });

    const t0 = Date.now();
    const nowSpy = jest.spyOn(Date, "now");
    nowSpy.mockReturnValue(t0);
    await expect(v.resolvePubkey("did:phoenix:x:y")).resolves.toBe(PUBKEY_A);

    nowSpy.mockReturnValue(t0 + 1001);
    await expect(v.resolvePubkey("did:phoenix:x:y")).resolves.toBe(PUBKEY_B);
    expect(f).toHaveBeenCalledTimes(2);
  });
});

describe("resolveKey — a revoked key is refused, not merely uncached", () => {
  it("throws key_revoked when status is not active", async () => {
    mockPubkey({ public_key_hex: PUBKEY_A, key_id: "k-1", status: "revoked" });
    const v = new PhoenixKeyVerifier({ phoenixkeyApiUrl: BASE });

    await expect(v.resolveKey("did:phoenix:x:y")).rejects.toMatchObject({
      code: "key_revoked",
    });
  });

  it("never caches a revoked key", async () => {
    const f = mockPubkey({ public_key_hex: PUBKEY_A, key_id: "k-1", status: "revoked" });
    const v = new PhoenixKeyVerifier({ phoenixkeyApiUrl: BASE });

    await expect(v.resolveKey("did:phoenix:x:y")).rejects.toThrow();
    await expect(v.resolveKey("did:phoenix:x:y")).rejects.toThrow();
    expect(f).toHaveBeenCalledTimes(2);
  });

  it("surfaces key_revoked as the verify reason, not a generic resolve failure", async () => {
    mockPubkey({ public_key_hex: PUBKEY_A, key_id: "k-1", status: "revoked" });
    const v = new PhoenixKeyVerifier({ phoenixkeyApiUrl: BASE });

    const r = await v.verifyIntent({
      user_did: "did:phoenix:x:y",
      intent: {
        action: "test",
        resource: "r",
        nonce: "n",
        timestamp: Math.floor(Date.now() / 1000),
      } as never,
      signature: "00",
    });
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/^key_revoked:/);
  });

  it("accepts status active in any casing", async () => {
    mockPubkey({ public_key_hex: PUBKEY_A, key_id: "k-1", status: "ACTIVE" });
    const v = new PhoenixKeyVerifier({ phoenixkeyApiUrl: BASE });
    await expect(v.resolvePubkey("did:phoenix:x:y")).resolves.toBe(PUBKEY_A);
  });
});
