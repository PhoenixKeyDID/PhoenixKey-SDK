import { ed25519 } from "@noble/curves/ed25519";
import { AppTokenVerifier } from "../src/verifier";
import { PhoenixKeyError } from "../src/types";

const KID = "phoenixkey-ed25519-1";

function base64Url(bytes: Uint8Array | string): string {
  const buf = typeof bytes === "string" ? Buffer.from(bytes, "utf8") : Buffer.from(bytes);
  return buf.toString("base64").replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

/** Builds a real Ed25519-signed JWT-shaped app_token using a fresh keypair. */
function makeSignedToken(
  privateKey: Uint8Array,
  opts: {
    header?: Record<string, unknown>;
    payload?: Record<string, unknown>;
    now?: number;
  } = {},
): string {
  const now = opts.now ?? Math.floor(Date.now() / 1000);
  const header = { alg: "EdDSA", kid: KID, typ: "JWT", ...opts.header };
  const payload = {
    iss: "https://api.phoenixkey.me",
    sub: "did:phoenix:0:abc123",
    aud: "did:phoenix:svc:orilife",
    iat: now,
    exp: now + 900,
    key_id: "11111111-1111-1111-1111-111111111111",
    key_role: "manager",
    ...opts.payload,
  };
  const headerB64 = base64Url(JSON.stringify(header));
  const payloadB64 = base64Url(JSON.stringify(payload));
  const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const signature = ed25519.sign(signingInput, privateKey);
  return `${headerB64}.${payloadB64}.${base64Url(signature)}`;
}

function jwksResponse(publicKey: Uint8Array, kid = KID) {
  return {
    keys: [
      {
        kty: "OKP",
        crv: "Ed25519",
        x: base64Url(publicKey),
        use: "sig",
        alg: "EdDSA",
        kid,
      },
    ],
  };
}

function mockFetchOnce(body: unknown, status = 200) {
  return jest.spyOn(globalThis, "fetch").mockImplementation(
    async () =>
      new Response(JSON.stringify(body), {
        status,
        headers: { "Content-Type": "application/json" },
      }),
  );
}

describe("AppTokenVerifier — verify() only trusts claims after signature check", () => {
  const privateKey = ed25519.utils.randomSecretKey();
  const publicKey = ed25519.getPublicKey(privateKey);

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it("accepts a validly-signed token and returns fail-safe-normalized claims", async () => {
    mockFetchOnce(jwksResponse(publicKey));
    const token = makeSignedToken(privateKey);
    const verifier = new AppTokenVerifier();

    const claims = await verifier.verify(token);

    expect(claims.sub).toBe("did:phoenix:0:abc123");
    expect(claims.aud).toBe("did:phoenix:svc:orilife");
    expect(claims.key_id).toBe("11111111-1111-1111-1111-111111111111");
    expect(claims.key_role).toBe("manager");
  });

  it("normalizes a missing key_role claim (pre-rollout token) to 'viewer', not 'owner'", async () => {
    mockFetchOnce(jwksResponse(publicKey));
    const token = makeSignedToken(privateKey, {
      payload: { key_role: undefined },
    });
    const verifier = new AppTokenVerifier();

    const claims = await verifier.verify(token);
    expect(claims.key_role).toBe("viewer");
  });

  it("REJECTS a token whose payload was tampered with after signing — never returns the forged claims", async () => {
    mockFetchOnce(jwksResponse(publicKey));
    const token = makeSignedToken(privateKey, { payload: { key_role: "viewer" } });
    const [headerB64, , sigB64] = token.split(".");

    // Attacker tries to escalate key_role by swapping the payload segment,
    // keeping the original (now-mismatched) signature.
    const forgedPayload = base64Url(
      JSON.stringify({
        iss: "https://api.phoenixkey.me",
        sub: "did:phoenix:0:abc123",
        aud: "did:phoenix:svc:orilife",
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 900,
        key_role: "owner",
      }),
    );
    const forgedToken = `${headerB64}.${forgedPayload}.${sigB64}`;

    const verifier = new AppTokenVerifier();
    await expect(verifier.verify(forgedToken)).rejects.toMatchObject({
      code: "signature_invalid",
    });
    await expect(verifier.verify(forgedToken)).rejects.toBeInstanceOf(PhoenixKeyError);
  });

  it("REJECTS a token signed by a different keypair than the one published in JWKS", async () => {
    const otherPrivateKey = ed25519.utils.randomSecretKey();
    mockFetchOnce(jwksResponse(publicKey)); // JWKS publishes the ORIGINAL pubkey
    const tokenFromWrongKey = makeSignedToken(otherPrivateKey);

    const verifier = new AppTokenVerifier();
    await expect(verifier.verify(tokenFromWrongKey)).rejects.toMatchObject({
      code: "signature_invalid",
    });
  });

  it("REJECTS an expired token even though its signature is valid", async () => {
    mockFetchOnce(jwksResponse(publicKey));
    const longAgo = Math.floor(Date.now() / 1000) - 10_000;
    const token = makeSignedToken(privateKey, {
      now: longAgo,
      payload: { iat: longAgo, exp: longAgo + 900 },
    });

    const verifier = new AppTokenVerifier();
    await expect(verifier.verify(token)).rejects.toMatchObject({ code: "token_expired" });
  });

  it("REJECTS a token minted for a different aud when expectedAud is given", async () => {
    mockFetchOnce(jwksResponse(publicKey));
    const token = makeSignedToken(privateKey, { payload: { aud: "did:phoenix:svc:other" } });

    const verifier = new AppTokenVerifier();
    await expect(verifier.verify(token, "did:phoenix:svc:orilife")).rejects.toMatchObject({
      code: "aud_mismatch",
    });
  });

  it("REJECTS a malformed token (wrong segment count) before ever hitting the network", async () => {
    const fetchSpy = mockFetchOnce(jwksResponse(publicKey));
    const verifier = new AppTokenVerifier();
    await expect(verifier.verify("not-a-jwt")).rejects.toMatchObject({
      code: "malformed_token",
    });
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("REJECTS an unrecognized kid (no matching JWKS entry)", async () => {
    mockFetchOnce(jwksResponse(publicKey, "some-other-kid"));
    const token = makeSignedToken(privateKey);
    const verifier = new AppTokenVerifier();
    await expect(verifier.verify(token)).rejects.toMatchObject({
      code: "jwks_key_not_found",
    });
  });

  it("caches JWKS across calls (does not re-fetch within TTL)", async () => {
    const fetchSpy = mockFetchOnce(jwksResponse(publicKey));
    const verifier = new AppTokenVerifier();
    await verifier.verify(makeSignedToken(privateKey));
    await verifier.verify(makeSignedToken(privateKey));
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });
});
