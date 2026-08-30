import { DeviceModule } from "../src/device";
import { PhoenixKeyError } from "../src/types";

const BASE = "https://api.example.test";

function mockFetch(impl: (url: string, init: RequestInit) => Promise<Response>) {
  return jest.spyOn(globalThis, "fetch").mockImplementation(impl as typeof fetch);
}

afterEach(() => {
  jest.restoreAllMocks();
});

describe("DeviceModule — requires a session token", () => {
  it("throws before making a network call when no session token is set", async () => {
    const fetchSpy = mockFetch(async () => {
      throw new Error("should not be called");
    });
    const mod = new DeviceModule(BASE, () => null);
    await expect(mod.listDevices()).rejects.toThrow(/session token/i);
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});

describe("DeviceModule — listDevices()", () => {
  it("sends Bearer session token and unwraps the DataResponse envelope", async () => {
    let seenAuth: string | null = null;
    let seenUrl = "";
    mockFetch(async (url, init) => {
      seenUrl = String(url);
      seenAuth = (init.headers as Record<string, string>).Authorization;
      return new Response(
        JSON.stringify({
          code: 1000,
          message: "ok",
          result: {
            devices: [
              {
                key_id: "k1",
                device_name: "My Phone",
                key_role: "owner",
                status: "active",
                created_at: "2026-01-01T00:00:00Z",
                last_used_at: null,
                current: true,
              },
            ],
          },
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    });

    const mod = new DeviceModule(BASE, () => "session-tok");
    const result = await mod.listDevices();

    expect(seenUrl).toBe(`${BASE}/keys/devices`);
    expect(seenAuth).toBe("Bearer session-tok");
    expect(result.devices).toHaveLength(1);
    expect(result.devices[0].key_id).toBe("k1");
  });

  it("maps KEY_ROLE_FORBIDDEN (1306) to PhoenixKeyError code 'key_role_forbidden'", async () => {
    mockFetch(
      async () =>
        new Response(JSON.stringify({ code: 1306, message: "Key role not permitted" }), {
          status: 403,
          headers: { "Content-Type": "application/json" },
        }),
    );
    const mod = new DeviceModule(BASE, () => "session-tok");
    await expect(mod.listDevices()).rejects.toMatchObject({ code: "key_role_forbidden" });
    await expect(mod.listDevices()).rejects.toBeInstanceOf(PhoenixKeyError);
  });
});

describe("DeviceModule — renameDevice()", () => {
  it("POSTs { device_name } to /keys/devices/{keyId}/name", async () => {
    let seenUrl = "";
    let seenBody = "";
    mockFetch(async (url, init) => {
      seenUrl = String(url);
      seenBody = String(init.body);
      return new Response(
        JSON.stringify({
          code: 1000,
          message: "ok",
          result: {
            key_id: "k1",
            device_name: "New Name",
            key_role: "owner",
            status: "active",
            created_at: "2026-01-01T00:00:00Z",
            last_used_at: null,
            current: true,
          },
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    });

    const mod = new DeviceModule(BASE, () => "session-tok");
    const result = await mod.renameDevice("k1", "New Name");

    expect(seenUrl).toBe(`${BASE}/keys/devices/k1/name`);
    expect(JSON.parse(seenBody)).toEqual({ device_name: "New Name" });
    expect(result.device_name).toBe("New Name");
  });

  it("maps DEVICE_NAME_INVALID (3012) to PhoenixKeyError code 'device_name_invalid'", async () => {
    mockFetch(
      async () =>
        new Response(JSON.stringify({ code: 3012, message: "Device name invalid" }), {
          status: 400,
          headers: { "Content-Type": "application/json" },
        }),
    );
    const mod = new DeviceModule(BASE, () => "session-tok");
    await expect(mod.renameDevice("k1", "")).rejects.toMatchObject({
      code: "device_name_invalid",
    });
  });

  it("maps KEY_NOT_FOUND (3002) to PhoenixKeyError code 'key_not_found'", async () => {
    mockFetch(
      async () =>
        new Response(JSON.stringify({ code: 3002, message: "Authorized key not found" }), {
          status: 404,
          headers: { "Content-Type": "application/json" },
        }),
    );
    const mod = new DeviceModule(BASE, () => "session-tok");
    await expect(mod.renameDevice("does-not-exist", "x")).rejects.toMatchObject({
      code: "key_not_found",
    });
  });
});

describe("DeviceModule — revokeDevice()", () => {
  it("POSTs to /keys/devices/{keyId}/revoke with Bearer token", async () => {
    let seenUrl = "";
    let seenMethod = "";
    mockFetch(async (url, init) => {
      seenUrl = String(url);
      seenMethod = String(init.method);
      return new Response(JSON.stringify({ code: 1000, message: "ok" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    });
    const mod = new DeviceModule(BASE, () => "session-tok");
    await mod.revokeDevice("k1");
    expect(seenUrl).toBe(`${BASE}/keys/devices/k1/revoke`);
    expect(seenMethod).toBe("POST");
  });

  it("maps LAST_OWNER_KEY (3008) to PhoenixKeyError code 'last_owner_key'", async () => {
    mockFetch(
      async () =>
        new Response(JSON.stringify({ code: 3008, message: "Cannot revoke last owner key" }), {
          status: 409,
          headers: { "Content-Type": "application/json" },
        }),
    );
    const mod = new DeviceModule(BASE, () => "session-tok");
    await expect(mod.revokeDevice("k1")).rejects.toMatchObject({ code: "last_owner_key" });
  });
});
