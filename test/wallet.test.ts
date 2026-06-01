import { paymentKeyHashFromAddress } from "../src/wallet";

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
