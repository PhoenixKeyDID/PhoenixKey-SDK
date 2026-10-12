import { PhoenixKeyClient } from "../src/client";
import { FeesModule } from "../src/fees";
import { NetworkModule } from "../src/network";
import { SupportModule } from "../src/support";

/**
 * Server: `GET /tx/estimate`, `GET /identity/nodes` and
 * `POST /support/session/init` are none of them in the public lists of
 * `AuthRequiredInterceptor` (PUBLIC_ANY_METHOD / PUBLIC_GET / PUBLIC_POST), so
 * without a Bearer session each answers 401 (code 1304). Each module therefore
 * reads the session token, refuses before the network when there is none, and
 * sends `Authorization: Bearer <token>` otherwise.
 */

const BASE = "https://api.example.test/api/v1";
const TOKEN = "session-token";
const DID = "did:phoenix:aaaaaaahl4nn6:" + "ab".repeat(32);

type Recorded = { url: string; method: string; headers: Headers };
const recorded: Recorded[] = [];

function mockOk(result: unknown) {
  recorded.length = 0;
  return jest.spyOn(globalThis, "fetch").mockImplementation((async (
    url: string,
    init?: RequestInit,
  ) => {
    recorded.push({
      url: String(url),
      method: init?.method ?? "GET",
      headers: new Headers(init?.headers),
    });
    return new Response(JSON.stringify({ code: 1000, message: "ok", result }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }) as unknown as typeof fetch);
}

afterEach(() => jest.restoreAllMocks());

describe("FeesModule.estimate — Bearer required", () => {
  it("sends Authorization: Bearer <token> on GET /tx/estimate", async () => {
    const spy = mockOk({ type: "create_did", magic: 12, unit: "MAGIC" });
    const fees = new FeesModule(BASE, () => TOKEN);
    const r = await fees.estimate("create_did");
    expect(spy).toHaveBeenCalledTimes(1);
    expect(recorded[0].url).toBe(`${BASE}/tx/estimate?type=create_did`);
    expect(recorded[0].headers.get("Authorization")).toBe(`Bearer ${TOKEN}`);
    expect(r.magic).toBe(12);
  });

  it("throws Not authenticated without a token and never calls the network", async () => {
    const spy = mockOk({});
    const fees = new FeesModule(BASE, () => null);
    await expect(fees.estimate("create_did")).rejects.toThrow("Not authenticated");
    expect(spy).not.toHaveBeenCalled();
  });
});

describe("NetworkModule.getNodes — Bearer required", () => {
  it("sends Authorization: Bearer <token> on GET /identity/nodes", async () => {
    const spy = mockOk({ nodes: [], total: 0 });
    const net = new NetworkModule(BASE, () => TOKEN);
    await net.getNodes();
    expect(spy).toHaveBeenCalledTimes(1);
    expect(recorded[0].url).toBe(`${BASE}/identity/nodes`);
    expect(recorded[0].headers.get("Authorization")).toBe(`Bearer ${TOKEN}`);
  });

  it("keeps the Bearer when a did filter is passed", async () => {
    mockOk({ nodes: [], total: 0 });
    const net = new NetworkModule(BASE, () => TOKEN);
    await net.getNodes(DID);
    expect(recorded[0].url).toBe(`${BASE}/identity/nodes?did=${encodeURIComponent(DID)}`);
    expect(recorded[0].headers.get("Authorization")).toBe(`Bearer ${TOKEN}`);
  });

  it("throws Not authenticated without a token and never calls the network", async () => {
    const spy = mockOk({});
    const net = new NetworkModule(BASE, () => null);
    await expect(net.getNodes()).rejects.toThrow("Not authenticated");
    await expect(net.getNodes(DID)).rejects.toThrow("Not authenticated");
    expect(spy).not.toHaveBeenCalled();
  });
});

describe("SupportModule.initSession — Bearer required", () => {
  it("sends Authorization: Bearer <token> on POST /support/session/init", async () => {
    const spy = mockOk({ session_id: "s1", proofchat_url: "https://proofchat.example/s1" });
    const support = new SupportModule(BASE, () => TOKEN);
    const r = await support.initSession();
    expect(spy).toHaveBeenCalledTimes(1);
    expect(recorded[0].url).toBe(`${BASE}/support/session/init`);
    expect(recorded[0].method).toBe("POST");
    expect(recorded[0].headers.get("Authorization")).toBe(`Bearer ${TOKEN}`);
    expect(r.session_id).toBe("s1");
  });

  it("throws Not authenticated without a token and never calls the network", async () => {
    const spy = mockOk({});
    const support = new SupportModule(BASE, () => null);
    await expect(support.initSession()).rejects.toThrow("Not authenticated");
    expect(spy).not.toHaveBeenCalled();
  });
});

describe("PhoenixKeyClient wires the session token into the three modules", () => {
  const store = new Map<string, string>();
  const g = globalThis as Record<string, unknown>;

  beforeEach(() => {
    store.clear();
    const localStorage = {
      getItem: (k: string) => (store.has(k) ? store.get(k)! : null),
      setItem: (k: string, v: string) => void store.set(k, String(v)),
      removeItem: (k: string) => void store.delete(k),
      clear: () => store.clear(),
    };
    Object.assign(g, { window: { localStorage }, localStorage });
  });

  afterEach(() => {
    delete g.window;
    delete g.localStorage;
  });

  function makeClient(): PhoenixKeyClient {
    return new PhoenixKeyClient({
      appId: "bearer-app",
      appName: "Bearer App",
      domain: "bearer.example",
      apiBaseUrl: BASE,
    });
  }

  it("sends the stored session token from fees, network and support", async () => {
    const spy = mockOk({ nodes: [], total: 0, type: "create_did", magic: 12, session_id: "s" });
    const client = makeClient();
    client.session.setSession(TOKEN, DID);

    await client.fees.estimate("create_did");
    await client.network.getNodes();
    await client.support.initSession();

    expect(spy).toHaveBeenCalledTimes(3);
    expect(recorded.map((r) => r.headers.get("Authorization"))).toEqual([
      `Bearer ${TOKEN}`,
      `Bearer ${TOKEN}`,
      `Bearer ${TOKEN}`,
    ]);
  });

  it("refuses all three before the network when logged out", async () => {
    const spy = mockOk({});
    const client = makeClient();
    await expect(client.fees.estimate("create_did")).rejects.toThrow("Not authenticated");
    await expect(client.network.getNodes()).rejects.toThrow("Not authenticated");
    await expect(client.support.initSession()).rejects.toThrow("Not authenticated");
    expect(spy).not.toHaveBeenCalled();
  });
});
