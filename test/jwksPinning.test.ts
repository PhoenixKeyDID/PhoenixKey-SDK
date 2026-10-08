import { ed25519 } from "@noble/curves/ed25519";
import { createHash } from "crypto";
import { AppTokenVerifier, ed25519JwkThumbprint } from "../src/verifier";
import { PhoenixKeyError } from "../src/types";

const KID = "phoenixkey-ed25519-1";
const AUD = "did:phoenix:svc:orilife";

function base64Url(bytes: Uint8Array | string): string {
  const buf = typeof bytes === "string" ? Buffer.from(bytes, "utf8") : Buffer.from(bytes);
  return buf.toString("base64").replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function makeToken(privateKey: Uint8Array, kid = KID): string {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "EdDSA", kid, typ: "JWT" };
  const payload = {
    iss: "https://api.phoenixkey.me",
    sub: "did:phoenix:0:abc123",
    aud: AUD,
    iat: now,
    exp: now + 900,
    key_role: "manager",
  };
  const h = base64Url(JSON.stringify(header));
  const p = base64Url(JSON.stringify(payload));
  const sig = ed25519.sign(new TextEncoder().encode(`${h}.${p}`), privateKey);
  return `${h}.${p}.${base64Url(sig)}`;
}

function jwk(publicKey: Uint8Array, kid = KID) {
  return { kty: "OKP", crv: "Ed25519", x: base64Url(publicKey), use: "sig", alg: "EdDSA", kid };
}

function mockJwks(keys: unknown[]) {
  return jest.spyOn(globalThis, "fetch").mockImplementation(
    async () =>
      new Response(JSON.stringify({ keys }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
  );
}

async function codeOf(p: Promise<unknown>): Promise<string> {
  try {
    await p;
  } catch (e) {
    expect(e).toBeInstanceOf(PhoenixKeyError);
    return (e as PhoenixKeyError).code;
  }
  throw new Error("expected rejection, got success");
}

describe("ed25519JwkThumbprint — RFC 7638 vectors", () => {
  it("matches RFC 8037 Appendix A.3 (public key from A.2)", () => {
    // RFC 8037 §A.2 public key and §A.3 thumbprint of that JWK.
    expect(
      ed25519JwkThumbprint({
        kty: "OKP",
        crv: "Ed25519",
        x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
      }),
    ).toBe("kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k");
  });

  it("ignores kid/use/alg and equals SHA-256 of the lexicographic canonical form", () => {
    const pub = ed25519.getPublicKey(ed25519.utils.randomSecretKey());
    const x = base64Url(pub);
    const expected = createHash("sha256")
      .update(`{"crv":"Ed25519","kty":"OKP","x":"${x}"}`)
      .digest("base64url");
    expect(ed25519JwkThumbprint(jwk(pub, "a"))).toBe(expected);
    expect(ed25519JwkThumbprint(jwk(pub, "b"))).toBe(expected);
  });

  it("rejects a non-Ed25519 JWK", () => {
    expect(() => ed25519JwkThumbprint({ kty: "EC", crv: "P-256", x: "AAAA" })).toThrow(PhoenixKeyError);
    expect(() => ed25519JwkThumbprint({ kty: "OKP", crv: "Ed25519", x: 'a"b' })).toThrow(PhoenixKeyError);
  });
});

describe("AppTokenVerifier — key pinning", () => {
  const goodPriv = ed25519.utils.randomSecretKey();
  const goodPub = ed25519.getPublicKey(goodPriv);
  const evilPriv = ed25519.utils.randomSecretKey();
  const evilPub = ed25519.getPublicKey(evilPriv);
  const goodPin = ed25519JwkThumbprint(jwk(goodPub));

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it("accepts a token signed by the pinned key", async () => {
    mockJwks([jwk(goodPub)]);
    const v = new AppTokenVerifier({ pinnedJwkThumbprints: [goodPin] });
    const claims = await v.verify(makeToken(goodPriv), AUD);
    expect(claims.sub).toBe("did:phoenix:0:abc123");
  });

  it("still accepts the pinned key when the JWKS also carries an extra key", async () => {
    mockJwks([jwk(evilPub, "evil-kid"), jwk(goodPub)]);
    const v = new AppTokenVerifier({ pinnedJwkThumbprints: [goodPin] });
    await expect(v.verify(makeToken(goodPriv), AUD)).resolves.toBeDefined();
  });

  it("rejects a token signed by a key injected into the JWKS, code jwks_key_not_pinned", async () => {
    // Attacker CDN serves JWKS = {real key, attacker key under a new kid} and
    // the attacker mints a perfectly valid signature with its own key.
    mockJwks([jwk(goodPub), jwk(evilPub, "evil-kid")]);
    const v = new AppTokenVerifier({ pinnedJwkThumbprints: [goodPin] });
    const code = await codeOf(v.verify(makeToken(evilPriv, "evil-kid"), AUD));
    expect(code).toBe("jwks_key_not_pinned");
  });

  it("does not fall back to the pinned key when the attacker reuses the real kid after its own key", async () => {
    // Same kid as the real key, attacker key listed FIRST. The attacker's
    // signature must not verify; the real key is the only candidate.
    mockJwks([jwk(evilPub, KID), jwk(goodPub, KID)]);
    const v = new AppTokenVerifier({ pinnedJwkThumbprints: [goodPin] });
    expect(await codeOf(v.verify(makeToken(evilPriv, KID), AUD))).toBe("signature_invalid");
    await expect(v.verify(makeToken(goodPriv, KID), AUD)).resolves.toBeDefined();
  });

  it("an unknown kid is still jwks_key_not_found, not not_pinned", async () => {
    mockJwks([jwk(goodPub)]);
    const v = new AppTokenVerifier({ pinnedJwkThumbprints: [goodPin] });
    expect(await codeOf(v.verify(makeToken(goodPriv, "nope"), AUD))).toBe("jwks_key_not_found");
  });

  it("throws at construction on an empty list", () => {
    expect(() => new AppTokenVerifier({ pinnedJwkThumbprints: [] })).toThrow(PhoenixKeyError);
    try {
      new AppTokenVerifier({ pinnedJwkThumbprints: [] });
    } catch (e) {
      expect((e as PhoenixKeyError).code).toBe("invalid_pinned_thumbprints");
    }
  });

  it("throws at construction on a malformed entry or a non-array", () => {
    expect(() => new AppTokenVerifier({ pinnedJwkThumbprints: ["short"] })).toThrow(PhoenixKeyError);
    expect(() => new AppTokenVerifier({ pinnedJwkThumbprints: [goodPin, ""] })).toThrow(PhoenixKeyError);
    expect(
      () => new AppTokenVerifier({ pinnedJwkThumbprints: goodPin as unknown as string[] }),
    ).toThrow(PhoenixKeyError);
    expect(
      () => new AppTokenVerifier({ pinnedJwkThumbprints: null as unknown as string[] }),
    ).toThrow(PhoenixKeyError);
  });

  it("without pinning: legacy behaviour (any JWKS key works) and exactly one warning per instance", async () => {
    mockJwks([jwk(evilPub, "evil-kid")]);
    const warn = jest.fn();
    const v = new AppTokenVerifier({ onWarning: warn });
    await expect(v.verify(makeToken(evilPriv, "evil-kid"), AUD)).resolves.toBeDefined();
    await expect(v.verify(makeToken(evilPriv, "evil-kid"), AUD)).resolves.toBeDefined();
    expect(warn).toHaveBeenCalledTimes(1);
    expect(String(warn.mock.calls[0][0])).toContain("pinnedJwkThumbprints");

    const other = new AppTokenVerifier({ onWarning: warn });
    await other.verify(makeToken(evilPriv, "evil-kid"), AUD);
    expect(warn).toHaveBeenCalledTimes(2);
  });

  it("without onWarning: falls back to a single console.warn", async () => {
    mockJwks([jwk(goodPub)]);
    const spy = jest.spyOn(console, "warn").mockImplementation(() => {});
    const v = new AppTokenVerifier();
    await v.verify(makeToken(goodPriv), AUD);
    await v.verify(makeToken(goodPriv), AUD);
    expect(spy).toHaveBeenCalledTimes(1);
  });

  it("with pinning: no warning", async () => {
    mockJwks([jwk(goodPub)]);
    const warn = jest.fn();
    const v = new AppTokenVerifier({ pinnedJwkThumbprints: [goodPin], onWarning: warn });
    await v.verify(makeToken(goodPriv), AUD);
    expect(warn).not.toHaveBeenCalled();
  });
});
