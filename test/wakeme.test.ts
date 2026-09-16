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

describe("wire keys match what the backend actually serialises", () => {
  // The backend DTOs carry no @JsonNaming override, so Spring's global
  // SNAKE_CASE applies. Jackson's SnakeCaseStrategy does NOT insert a
  // separator between two consecutive capitals, so:
  //     initialDLamp → initial_dlamp        currentDLamp → current_dlamp
  // Checked against jackson-databind 2.17.2 by serialising copies of
  // VaultStatusResponse / PotStatusResponse, not by reading the algorithm.
  //
  // These assertions are deliberately written so that renaming the property
  // back to the underscored spelling is a *compile* error as well as a
  // failing expectation — `tsc --noEmit` goes red before jest does.

  it("vault status exposes initial_dlamp — the underscored spelling is not sent", async () => {
    mockOk({ initial_dlamp: 1001, owned_lamp: 0, d_unit: 1_000_000 });
    const v = await mod().getVaultStatus("did:phoenix:x:y");
    expect(v.initial_dlamp).toBe(1001);
    expect((v as unknown as Record<string, unknown>).initial_d_lamp).toBeUndefined();
  });

  it("pot status exposes current_dlamp — the underscored spelling is not sent", async () => {
    mockOk({ current_dlamp: 500, d_cap: 1001 });
    const p = await mod().getPotStatus();
    expect(p.current_dlamp).toBe(500);
    expect((p as unknown as Record<string, unknown>).current_d_lamp).toBeUndefined();
  });

  it("build response carries every required signer, not just the first", async () => {
    mockOk({ required_signer_key_hashes: ["controller_pkh", "device_pkh"] });
    const b = await mod().buildGetLamp({ wallet_address: "addr_test1abc" });
    // GetLAMP needs both; signing only the first yields a chain-rejected tx
    // whose error does not name the missing key (Issue #282).
    expect(b.required_signer_key_hashes).toEqual(["controller_pkh", "device_pkh"]);
    expect(
      (b as unknown as Record<string, unknown>).required_signer_key_hash,
    ).toBeUndefined();
  });
});

describe("ActivationModule alias", () => {
  it("is the same class, not a wrapper", () => {
    expect(ActivationModule).toBe(WakemeModule);
    expect(new ActivationModule(BASE, BASE, () => TOKEN)).toBeInstanceOf(WakemeModule);
  });
});
