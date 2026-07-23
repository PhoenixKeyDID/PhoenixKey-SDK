import { PhoenixKeyClient } from "../src/client";
import { PhoenixKeyVerifier } from "../src/verifier";

/**
 * The backend serves every route under the `/api/v1` context path — the bare
 * origin returns 404 with no body. A default that omits the prefix makes every
 * call fail for anyone who does not override it, so pin it here.
 */
describe("default API base URL carries the /api/v1 context path", () => {
  it("client defaults to the prefixed origin", () => {
    const client = new PhoenixKeyClient({
      appId: "test-app",
      appName: "Test App",
      domain: "test.example",
    });

    expect(client.config.apiBaseUrl).toBe("https://api.phoenixkey.me/api/v1");
    expect(client.config.sseBaseUrl).toBe("https://api.phoenixkey.me/api/v1");
  });

  it("an explicit base URL still wins", () => {
    const client = new PhoenixKeyClient({
      appId: "test-app",
      appName: "Test App",
      domain: "test.example",
      apiBaseUrl: "http://localhost:8080/api/v1",
    });

    expect(client.config.apiBaseUrl).toBe("http://localhost:8080/api/v1");
  });

  it("verifier resolves pubkeys under the prefixed origin", async () => {
    const verifier = new PhoenixKeyVerifier({});
    const fetchMock = jest
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(
        new Response(JSON.stringify({ code: 1000, result: { public_key_hex: "00" } }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
      );

    try {
      await verifier
        .resolvePubkey("did:phoenix:aaaaaaaaaaaaa:" + "a".repeat(64))
        .catch(() => undefined);

      const calledUrl = String(fetchMock.mock.calls[0]?.[0] ?? "");
      expect(calledUrl.startsWith("https://api.phoenixkey.me/api/v1/identity/")).toBe(true);
    } finally {
      fetchMock.mockRestore();
    }
  });
});
