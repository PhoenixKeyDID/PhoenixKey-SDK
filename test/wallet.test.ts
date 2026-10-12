import { paymentKeyHashFromAddress, WalletModule } from "../src/wallet";

describe("WalletModule — MAGIC claim removed", () => {
  it("exposes no claimMagic (server answers 410 MAGIC_CLAIM_DEPRECATED)", () => {
    const w = new WalletModule("http://x", () => null) as unknown as Record<string, unknown>;
    expect(w.claimMagic).toBeUndefined();
  });
});

// ─── Local bech32 encoder (test-only) to build valid CIP-19 vectors ──────────
const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

function polymod(values: number[]): number {
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk ^= GEN[i];
  }
  return chk >>> 0;
}
function hrpExpand(hrp: string): number[] {
  const out: number[] = [];
  for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) >>> 5);
  out.push(0);
  for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) & 0x1f);
  return out;
}
function toWords(bytes: number[]): number[] {
  let acc = 0;
  let bits = 0;
  const out: number[] = [];
  for (const b of bytes) {
    acc = (acc << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out.push((acc >> bits) & 0x1f);
    }
  }
  if (bits > 0) out.push((acc << (5 - bits)) & 0x1f);
  return out;
}
function bech32Encode(hrp: string, data5: number[]): string {
  const values = [...hrpExpand(hrp), ...data5];
  const mod = polymod([...values, 0, 0, 0, 0, 0, 0]) ^ 1;
  const checksum: number[] = [];
  for (let i = 0; i < 6; i++) checksum.push((mod >> (5 * (5 - i))) & 0x1f);
  let out = hrp + "1";
  for (const v of [...data5, ...checksum]) out += CHARSET[v];
  return out;
}

const PAY_PKH = Array.from({ length: 28 }, (_, i) => i + 1); // 0x01..0x1c
const STAKE_CRED = Array.from({ length: 28 }, (_, i) => 0x80 + i);
const PAY_HEX = PAY_PKH.map((b) => b.toString(16).padStart(2, "0")).join("");

/** header byte = (type << 4) | network(0=testnet/1=mainnet) */
function addr(hrp: string, type: number, net: number, body: number[]): string {
  const header = (type << 4) | (net & 0x0f);
  return bech32Encode(hrp, toWords([header, ...body]));
}

describe("paymentKeyHashFromAddress — payment types", () => {
  it("extracts PKH from a base address (type 0, key-key)", () => {
    const a = addr("addr_test", 0, 0, [...PAY_PKH, ...STAKE_CRED]);
    expect(paymentKeyHashFromAddress(a)).toBe(PAY_HEX);
  });

  it("extracts PKH from an enterprise address (type 6, key-only)", () => {
    const a = addr("addr_test", 6, 0, PAY_PKH);
    expect(paymentKeyHashFromAddress(a)).toBe(PAY_HEX);
  });

  it("extracts PKH from a pointer address (type 4)", () => {
    const a = addr("addr_test", 4, 0, [...PAY_PKH, 0x01, 0x02, 0x03]);
    expect(paymentKeyHashFromAddress(a)).toBe(PAY_HEX);
  });
});

describe("paymentKeyHashFromAddress — script payment credential rejected", () => {
  it.each([1, 3, 5, 7])("rejects script payment type %i", (type) => {
    const a = addr("addr_test", type, 0, [...PAY_PKH, ...STAKE_CRED]);
    expect(() => paymentKeyHashFromAddress(a)).toThrow(/script hash/);
  });
});

describe("paymentKeyHashFromAddress — reward/stake addresses rejected (the bug)", () => {
  it("rejects a reward key address (type 14)", () => {
    // type 14 = 0b1110: `14 & 1 == 0` so the OLD code would have returned the
    // stake credential as a bogus payment PKH. New code must reject it.
    const a = addr("stake_test", 14, 0, STAKE_CRED);
    expect(() => paymentKeyHashFromAddress(a)).toThrow(/not a payment address/);
  });

  it("rejects a reward script address (type 15)", () => {
    const a = addr("stake_test", 15, 0, STAKE_CRED);
    expect(() => paymentKeyHashFromAddress(a)).toThrow(/not a payment address/);
  });
});

describe("paymentKeyHashFromAddress — bech32 checksum (BIP-173)", () => {
  it("rejects a single mistyped character", () => {
    const good = addr("addr_test", 0, 0, [...PAY_PKH, ...STAKE_CRED]);
    // Flip one data char (avoid the hrp + separator).
    const idx = good.length - 10;
    const ch = good[idx];
    const repl = ch === "q" ? "p" : "q";
    const bad = good.slice(0, idx) + repl + good.slice(idx + 1);
    expect(bad).not.toBe(good);
    expect(() => paymentKeyHashFromAddress(bad)).toThrow(/checksum/);
  });

  it("rejects mixed-case input", () => {
    const good = addr("addr_test", 0, 0, [...PAY_PKH, ...STAKE_CRED]);
    // Uppercase a letter that actually changes case (digits don't).
    const i = good.split("").findIndex((c, k) => k > 10 && /[a-z]/.test(c));
    expect(i).toBeGreaterThan(-1);
    const mixed = good.slice(0, i) + good[i].toUpperCase() + good.slice(i + 1);
    expect(mixed).not.toBe(good);
    expect(() => paymentKeyHashFromAddress(mixed)).toThrow(/mixed case/);
  });

  it("rejects an invalid bech32 char", () => {
    expect(() => paymentKeyHashFromAddress("addr_test1bbb")).toThrow(/Invalid bech32 char|too short|checksum/);
  });

  it("rejects a string with no separator", () => {
    expect(() => paymentKeyHashFromAddress("notbech32")).toThrow(/separator|checksum/);
  });
});

// ─── Auth on balance / all reads ─────────────────────────────────────────────
// Server: WalletController.balance and getAllWallets both call requireSelfDid
// and need a Bearer session — an unauthenticated call is always 401.

const WBASE = "https://api.example.test/api/v1";
const WTOKEN = "session-token";
const WDID = "did:phoenix:aaaaaaahl4nn6:" + "ab".repeat(32);

type Recorded = { url: string; headers: Headers };
const recorded: Recorded[] = [];

function mockWalletOk(result: unknown) {
  recorded.length = 0;
  return jest.spyOn(globalThis, "fetch").mockImplementation((async (
    url: string,
    init?: RequestInit,
  ) => {
    recorded.push({ url: String(url), headers: new Headers(init?.headers) });
    return new Response(JSON.stringify({ code: 1000, message: "ok", result }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }) as unknown as typeof fetch);
}

describe("WalletModule.getBalance — Bearer required", () => {
  afterEach(() => jest.restoreAllMocks());

  it("sends Authorization: Bearer <token> and keeps string quantities", async () => {
    const spy = mockWalletOk({
      address: "addr_test1qz",
      balance_lovelace: "5000000",
      balance_lamp: "36000000000000000",
      balance_carp: "0",
      balance_magic: "0",
      magic_accrued: "0",
      magic_rate_per_slot: "",
      last_accrual_slot: 0,
      current_slot: 123,
    });
    const w = new WalletModule(WBASE, () => WTOKEN);
    const b = await w.getBalance(WDID);
    expect(spy).toHaveBeenCalledTimes(1);
    expect(recorded[0].headers.get("Authorization")).toBe(`Bearer ${WTOKEN}`);
    expect(recorded[0].url).toBe(`${WBASE}/wallet/${encodeURIComponent(WDID)}/balance`);
    expect(b.balance_lamp).toBe("36000000000000000");
    expect(BigInt(b.balance_lamp)).toBeGreaterThan(BigInt(Number.MAX_SAFE_INTEGER));
  });

  it("throws Not authenticated without a token and never calls the network", async () => {
    const spy = mockWalletOk({});
    const w = new WalletModule(WBASE, () => null);
    await expect(w.getBalance(WDID)).rejects.toThrow("Not authenticated");
    expect(spy).not.toHaveBeenCalled();
  });

  it("resolveOwnerPkh needs the session too (no network without a token)", async () => {
    const spy = mockWalletOk({});
    const w = new WalletModule(WBASE, () => null);
    await expect(w.resolveOwnerPkh(WDID)).rejects.toThrow("Not authenticated");
    expect(spy).not.toHaveBeenCalled();
  });

  it("resolveOwnerPkh returns the payment key hash when the session is valid", async () => {
    mockWalletOk({ address: addr("addr_test", 6, 0, PAY_PKH), balance_lovelace: "0" });
    const w = new WalletModule(WBASE, () => WTOKEN);
    await expect(w.resolveOwnerPkh(WDID)).resolves.toBe(PAY_HEX);
    expect(recorded[0].headers.get("Authorization")).toBe(`Bearer ${WTOKEN}`);
  });
});

describe("WalletModule.getAll — GET /wallet/{did}/all", () => {
  afterEach(() => jest.restoreAllMocks());

  const ALL = {
    wallets: [
      {
        kind: "phoenix",
        addresses: { fixed: "addr_test1qfixed" },
        balances: { lovelace: "2000000", lamp: "1000", carp: "0" },
      },
      {
        kind: "standard",
        addresses: { fixed: "addr_test1qs", active: "addr_test1qa", stake: "stake_test1u" },
        balances: { lovelace: "0", lamp: "0", carp: "7" },
      },
    ],
    magic: {
      source: "unwired",
      available: null,
      accrued: null,
      expired: null,
      vault_count: null,
      magic_absent_reason: "NOT_CONFIGURED",
    },
    vault: null,
    vault_absent_reason: "SERVED_BY_WAKEME_SERVICE",
  };

  it("calls /wallet/<did>/all with Bearer and returns the server shape", async () => {
    mockWalletOk(ALL);
    const w = new WalletModule(WBASE, () => WTOKEN);
    const r = await w.getAll(WDID);
    expect(recorded).toHaveLength(1);
    expect(recorded[0].url).toBe(`${WBASE}/wallet/${encodeURIComponent(WDID)}/all`);
    expect(recorded[0].headers.get("Authorization")).toBe(`Bearer ${WTOKEN}`);
    expect(r).toEqual(ALL);
    expect(r.wallets[1].addresses.stake).toBe("stake_test1u");
    expect(r.magic.source).toBe("unwired");
    expect(r.vault).toBeNull();
    expect(r.vault_absent_reason).toBe("SERVED_BY_WAKEME_SERVICE");
  });

  it("returns a populated vault block with string quantities", async () => {
    const vault = {
      owned_lamp: "1",
      conditional_lamp: "1001000000",
      reclaimed_to_pot: "0",
      d_unit: "1000000",
    };
    mockWalletOk({ ...ALL, vault, vault_absent_reason: null });
    const r = await new WalletModule(WBASE, () => WTOKEN).getAll(WDID);
    expect(r.vault).toEqual(vault);
    expect(r.vault_absent_reason).toBeNull();
  });

  it("throws Not authenticated without a token and never calls the network", async () => {
    const spy = mockWalletOk(ALL);
    await expect(new WalletModule(WBASE, () => null).getAll(WDID)).rejects.toThrow(
      "Not authenticated",
    );
    expect(spy).not.toHaveBeenCalled();
  });

  it("encodes a DID with special characters in the path", async () => {
    mockWalletOk(ALL);
    const odd = "did:phoenix:a/b?c#d e";
    await new WalletModule(WBASE, () => WTOKEN).getAll(odd);
    expect(recorded[0].url).toBe(`${WBASE}/wallet/did%3Aphoenix%3Aa%2Fb%3Fc%23d%20e/all`);
    mockWalletOk({ address: null });
    await new WalletModule(WBASE, () => WTOKEN).getBalance(odd);
    expect(recorded[0].url).toBe(`${WBASE}/wallet/did%3Aphoenix%3Aa%2Fb%3Fc%23d%20e/balance`);
  });
});
