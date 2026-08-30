import { WakemeModule, ActivationModule } from "../src/wakeme";

const BASE = "https://api.example.test/api/v1";
const TOKEN = "session-token";

afterEach(() => {
  jest.restoreAllMocks();
});

const calls: string[] = [];

function mockOk(result: unknown = {}) {
  calls.length = 0;
  return jest.spyOn(globalThis, "fetch").mockImplementation((async (url: string) => {
    calls.push(String(url));
    return new Response(JSON.stringify({ code: 1000, message: "ok", result }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }) as unknown as typeof fetch);
}

function mod(token: string | null = TOKEN) {
  return new WakemeModule(BASE, BASE, () => token);
}

describe("WakemeModule — model A routes live under /wakeme", () => {
  it("build hits /wakeme/build", async () => {
    mockOk();
    await mod().buildGetLamp({ wallet_address: "addr_test1abc" });
    expect(calls[0]).toBe(`${BASE}/wakeme/build`);
  });

  it("submit hits /wakeme/submit and sends snake_case signed_tx_cbor", async () => {
    const f = mockOk();
    await mod().submitGetLamp("deadbeef");
    expect(calls[0]).toBe(`${BASE}/wakeme/submit`);
    const init = f.mock.calls[0][1] as RequestInit;
    expect(JSON.parse(String(init.body))).toEqual({ signed_tx_cbor: "deadbeef" });
  });

  it("vault status / magic / pot / gen-entry hit their /wakeme paths", async () => {
    mockOk();
    const m = mod();
    const did = "did:phoenix:aaaaaaaiusdea:ab";
    await m.getVaultStatus(did);
    await m.getVaultMagic(did);
    await m.getPotStatus();
    await m.getGenEntry(did);
    expect(calls).toEqual([
      `${BASE}/wakeme/vault/${encodeURIComponent(did)}`,
      `${BASE}/wakeme/vault/${encodeURIComponent(did)}/magic`,
      `${BASE}/wakeme/pot`,
      `${BASE}/wakeme/gen-entry?did=${encodeURIComponent(did)}`,
    ]);
  });

  it("GetMAGIC quote / checkout / order hit their /wakeme paths", async () => {
    mockOk();
    const m = mod();
    await m.quoteMagic({ fiat_currency: "VND", fiat_amount: 200000 });
    await m.checkoutMagic("q-1", "vietqr");
    await m.getMagicOrder("o-1");
    expect(calls).toEqual([
      `${BASE}/wakeme/getmagic/quote`,
      `${BASE}/wakeme/getmagic/checkout`,
      `${BASE}/wakeme/getmagic/o-1`,
    ]);
  });

  it("a DID with a colon is percent-encoded into the path", async () => {
    mockOk();
    await mod().getVaultStatus("did:phoenix:x:y");
    expect(calls[0]).toBe(`${BASE}/wakeme/vault/did%3Aphoenix%3Ax%3Ay`);
  });

  it("refuses to call an authenticated route with no session", async () => {
    mockOk();
    await expect(
      mod(null).buildGetLamp({ wallet_address: "addr_test1abc" }),
    ).rejects.toThrow("Not authenticated");
    expect(calls).toHaveLength(0);
  });
});

describe("WakemeModule — retired VND/Genie flow still answers on /activation", () => {
  it("initiate stays on /activation/initiate — it has no /wakeme counterpart", async () => {
    mockOk();
    await mod().initiate("addr_test1abc");
    expect(calls[0]).toBe(`${BASE}/activation/initiate`);
  });

  it("submitTx stays on /activation/{id}/submit-tx", async () => {
    mockOk();
    await mod().submitTx("a-1", "beef");
    expect(calls[0]).toBe(`${BASE}/activation/a-1/submit-tx`);
  });
});

describe("ActivationModule alias", () => {
  it("is the same class, not a wrapper", () => {
    expect(ActivationModule).toBe(WakemeModule);
    expect(new ActivationModule(BASE, BASE, () => TOKEN)).toBeInstanceOf(WakemeModule);
  });
});
