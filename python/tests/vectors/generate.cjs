#!/usr/bin/env node
/**
 * Generates `vectors.json`, the cross-language test vectors for the Python client.
 *
 * Every expected value in the output is produced by running the TypeScript SDK
 * itself (`src/verifier.ts`, `src/envelope.ts`), not by re-implementing its rules:
 *
 *   - the TypeScript sources are compiled to `./.build` (CommonJS) with the
 *     repo's own TypeScript compiler;
 *   - `PhoenixKeyVerifier` / `AppTokenVerifier` are run against a scripted
 *     `fetch` and a frozen clock, and whatever they answer is recorded;
 *   - the canonical JSON bytes are captured from the exact buffer the verifier
 *     hands to SHA-256 (the TypeScript function is not exported).
 *
 * Keys are derived from fixed labels, and both ECDSA (RFC 6979) and Ed25519 are
 * deterministic, so re-running this script reproduces the file byte for byte.
 *
 * Usage (from the repository root, after `npm install`):
 *
 *     node python/tests/vectors/generate.cjs
 */
"use strict";

const fs = require("fs");
const path = require("path");
const cp = require("child_process");

const HERE = __dirname;
const ROOT = path.resolve(HERE, "..", "..", "..");
const BUILD = path.join(HERE, ".build");
const OUT = path.join(HERE, "vectors.json");

// ── 1. Compile the TypeScript under test ──────────────────────────────────────
fs.rmSync(BUILD, { recursive: true, force: true });
cp.execFileSync(
  process.execPath,
  [
    require.resolve("typescript/bin/tsc", { paths: [ROOT] }),
    "--outDir", BUILD,
    "--module", "commonjs",
    "--moduleResolution", "node10",
    "--target", "ES2022",
    "--lib", "ES2022,DOM",
    "--skipLibCheck",
    "--esModuleInterop",
    "--strict",
    "--declaration", "false",
    "--sourceMap", "false",
    "--rootDir", path.join(ROOT, "src"),
    path.join(ROOT, "src", "verifier.ts"),
    path.join(ROOT, "src", "types.ts"),
    path.join(ROOT, "src", "envelope.ts"),
  ],
  { cwd: ROOT, stdio: "inherit" },
);

// ── 2. Hook SHA-256 so the canonical bytes can be read back ───────────────────
const sha256mod = require("@noble/hashes/sha256");
const sha256Orig = sha256mod.sha256;
let capture = null;
sha256mod.sha256 = Object.assign(function (msg, ...rest) {
  if (capture) capture.push(Uint8Array.from(msg));
  return sha256Orig(msg, ...rest);
}, sha256Orig);

const { p256 } = require("@noble/curves/p256");
const { ed25519 } = require("@noble/curves/ed25519");
const V = require(path.join(BUILD, "verifier.js"));
const E = require(path.join(BUILD, "envelope.js"));

// ── 3. Frozen clock and scripted network ──────────────────────────────────────
const FIXED_NOW = 1760000000; // 2025-10-09T08:53:20Z
let NOW = FIXED_NOW;
Date.now = () => NOW * 1000;

const API = "https://api.example.test/api/v1";
let handler = null;
let exchanges = [];
globalThis.fetch = async (input) => {
  const url = String(input);
  if (!handler) throw new Error("unexpected network call: " + url);
  const r = handler(url);
  exchanges.push({ url, status: r.status, body: r.body });
  return new Response(r.body, { status: r.status, headers: { "Content-Type": "application/json" } });
};

// ── helpers ───────────────────────────────────────────────────────────────────
const utf8 = (s) => new TextEncoder().encode(s);
const hex = (b) => Buffer.from(b).toString("hex");
const b64url = (b) => Buffer.from(b).toString("base64url");
const flipLastBit = (h) => h.slice(0, -2) + (parseInt(h.slice(-2), 16) ^ 1).toString(16).padStart(2, "0");

function p256Device(label) {
  const priv = sha256Orig(utf8("phoenixkey-sdk-python-vectors/p256/" + label));
  if (!p256.utils.isValidPrivateKey(priv)) throw new Error("bad scalar for " + label);
  return {
    label,
    priv,
    compressed: hex(p256.getPublicKey(priv, true)),
    uncompressed: hex(p256.getPublicKey(priv, false)),
  };
}

function signAll(dev, messageBytes) {
  const sig = p256.sign(sha256Orig(messageBytes), dev.priv);
  const low = sig.hasHighS() ? sig.normalizeS() : sig;
  const high = low.hasHighS() ? low : new p256.Signature(low.r, p256.CURVE.n - low.s);
  const der = (s) => (s.toDERHex ? s.toDERHex() : hex(s.toBytes("der")));
  return {
    compact: hex(low.toCompactRawBytes()),
    der: der(low),
    compactHighS: hex(high.toCompactRawBytes()),
    derHighS: der(high),
  };
}

const record = (pub, role, status, revokedAt) => ({
  public_key_hex: pub,
  key_role: role,
  key_id: "00000000-0000-4000-8000-" + pub.slice(2, 14),
  status,
  created_at: "2026-01-01T00:00:00Z",
  revoked_at: revokedAt ?? null,
});

const ok = (result) => ({ status: 200, body: JSON.stringify({ code: 1000, message: "ok", result }) });
const notFound = () => ({ status: 404, body: JSON.stringify({ code: 1304, message: "KEY_NOT_FOUND" }) });

/** Scripted server: no `?key=` -> last record; `?key=` -> that exact key or 404. */
function recordsServer(records) {
  return (url) => {
    const want = new URL(url).searchParams.get("key");
    const rec = want
      ? records.find((r) => r.public_key_hex.toLowerCase().replace(/^0x/, "") === want)
      : records[records.length - 1];
    return rec ? ok(rec) : notFound();
  };
}

const DID = "did:phoenix:aaaaaaaaaaaaa:" + "0".repeat(64);
const devA = p256Device("device-a");
const devB = p256Device("device-b");
const devC = p256Device("device-c");

function mkIntent(over = {}) {
  return {
    type: "TRANSFER",
    body: { to: "addr_test1qz...", amount: "1000000", memo: "café ☕" },
    domain: "example.test",
    nonce: "ab".repeat(16),
    timestamp: FIXED_NOW,
    display_text: "Send 1 ADA",
    ...over,
  };
}

/** Canonical bytes exactly as `PhoenixKeyVerifier.verifyIntent` builds them. */
async function tsCanonical(intentObj) {
  capture = [];
  handler = () => ok(record(devA.compressed, "owner", "active"));
  exchanges = [];
  NOW = intentObj.timestamp;
  try {
    await new V.PhoenixKeyVerifier({ phoenixkeyApiUrl: API }).verifyIntent({
      user_did: DID,
      intent: intentObj,
      signature: "00".repeat(64),
    });
  } finally {
    NOW = FIXED_NOW;
  }
  const got = capture;
  capture = null;
  if (got.length !== 1) throw new Error("expected exactly one SHA-256 call, saw " + got.length);
  return got[0];
}

function summarize(res) {
  const out = { valid: res.valid };
  if (res.reason !== undefined) out.reason = res.reason;
  if (res.envelope !== undefined) out.envelope = res.envelope;
  return out;
}

// ── 4. Canonical JSON vectors ─────────────────────────────────────────────────
async function buildCanonical() {
  const bodies = {
    key_order_nested: '{"z":1,"a":{"y":[3,2,1],"b":null},"m":true}',
    key_order_utf16_astral_vs_bmp:
      '{"\\ud83d\\ude00":1,"\\uff5e":2,"\\ue000":3,"\\uffff":4,"z":5,"Z":6,"é":7,"e":8,"":9,"10":10,"9":11,"a b":12}',
    key_order_surrogate_pair_vs_fffd: '{"\\ud83d\\ude00":"smile","\\ufffd":"repl","\\ud7ff":"low"}',
    key_order_decomposed_vs_precomposed: '{"e\\u0301":1,"\\u00e9":2}',
    keys_with_escapes: '{"a\\"b":1,"a\\\\b":2,"a\\nb":3,"a\\u0001b":4}',
    numbers_integers: '{"a":0,"b":-0,"c":-7,"d":100,"e":9007199254740991,"f":9007199254740993,"g":12345678901234567890}',
    numbers_floats: '{"a":1.0,"b":1.5,"c":0.1,"d":0.30000000000000004,"e":4.35,"f":100.0,"g":1E2,"h":12e0,"i":-1.25e-8}',
    numbers_exponent_thresholds:
      '{"a":1e21,"b":1e20,"c":123456789012345680000,"d":1.2345e25,"e":1e-7,"f":0.000001,"g":1.5e-10,"h":5e-324,"i":1e300,"j":1.7976931348623157e308}',
    numbers_overflow_to_infinity: '{"a":1e400,"b":-1e400}',
    booleans_null_empty: '{"t":true,"f":false,"n":null,"o":{},"a":[],"s":""}',
    arrays_mixed: '{"a":[1,"two",[3,{"b":2,"a":1}],null,true,{"z":[]}]}',
    string_escapes: '{"a":"q\\" b\\\\ s\\/ \\b\\f\\n\\r\\t"}',
    string_controls: '{"a":"\\u0000\\u0001\\u001f\\u007f\\u0080"}',
    string_line_separators: '{"a":"\\u2028\\u2029 line\\u2028sep"}',
    string_unicode: '{"a":"héllo wörld ☕ 日本語 \\ud83d\\ude00 \\u00e9 e\\u0301"}',
    string_lone_surrogates: '{"hi":"\\ud800","lo":"\\udc00","mix":"a\\udbffb"}',
    duplicate_keys_last_wins: '{"a":1,"a":2,"b":{"c":1,"c":3}}',
    deep_nesting: '{"a":{"b":{"c":{"d":{"e":{"f":[[[[[1]]]]]}}}}}}',
  };
  const cases = [];
  for (const [name, bodyJson] of Object.entries(bodies)) {
    const intentJson =
      '{"type":"CUSTOM","body":' + bodyJson + ',"domain":"example.test","nonce":"00","timestamp":' +
      FIXED_NOW + ',"display_text":"x"}';
    const bytes = await tsCanonical(JSON.parse(intentJson));
    cases.push({ name, intent_json: intentJson, expected_hex: hex(bytes), expected_utf8_lossy: Buffer.from(bytes).toString("utf8") });
  }
  // body absent / null at the intent level, and extra top-level keys
  for (const [name, intentJson] of [
    ["body_absent", '{"type":"T","domain":"d","nonce":"n","timestamp":' + FIXED_NOW + ',"display_text":"x"}'],
    ["body_null", '{"type":"T","body":null,"domain":"d","nonce":"n","timestamp":' + FIXED_NOW + ',"display_text":"x"}'],
    ["app_id_present", '{"type":"T","app_id":"app","domain":"d","nonce":"n","timestamp":' + FIXED_NOW + ',"display_text":"x"}'],
    ["whitespace_in_source_json", ' {  "type" : "T" ,\n "domain":"d" , "nonce":"n","timestamp":' + FIXED_NOW + ' , "display_text":"x" }'],
  ]) {
    const bytes = await tsCanonical(JSON.parse(intentJson));
    cases.push({ name, intent_json: intentJson, expected_hex: hex(bytes), expected_utf8_lossy: Buffer.from(bytes).toString("utf8") });
  }
  return cases;
}

// ── 5. Envelope vectors ───────────────────────────────────────────────────────
function buildEnvelope() {
  const fieldsets = [
    { name: "ascii", user_did: DID, domain: "example.test", challenge: "abc123", timestamp: FIXED_NOW },
    { name: "empty_strings", user_did: "", domain: "", challenge: "", timestamp: 0 },
    { name: "unicode", user_did: "did:phoenix:é", domain: "日本語.test", challenge: "☕😀", timestamp: FIXED_NOW },
    { name: "colon_collision_a", user_did: DID, domain: "b:c", challenge: "a", timestamp: FIXED_NOW },
    { name: "colon_collision_b", user_did: DID, domain: "c", challenge: "a:b", timestamp: FIXED_NOW },
    { name: "timestamp_beyond_2038", user_did: DID, domain: "example.test", challenge: "c", timestamp: 4102444800 },
    { name: "timestamp_2_pow_40", user_did: DID, domain: "example.test", challenge: "c", timestamp: 2 ** 40 },
    { name: "timestamp_max_safe", user_did: DID, domain: "example.test", challenge: "c", timestamp: Number.MAX_SAFE_INTEGER },
  ];
  return fieldsets.map((f) => {
    const { name, ...fields } = f;
    return {
      name,
      fields,
      v1_hex: hex(E.encodeRpAuthV1(fields)),
      legacy_hex: hex(E.encodeLegacyConcat(fields)),
    };
  });
}

// ── 6. verifyIntent / verifyAuthProof vectors ─────────────────────────────────
async function runVerify(kind, c) {
  handler = c.handler;
  exchanges = [];
  NOW = c.now ?? FIXED_NOW;
  const verifier = new V.PhoenixKeyVerifier({
    phoenixkeyApiUrl: c.api_url ?? API,
    ...(c.accept_legacy_envelope === undefined ? {} : { acceptLegacyEnvelope: c.accept_legacy_envelope }),
  });
  let res;
  try {
    res = kind === "intent" ? await verifier.verifyIntent(c.request) : await verifier.verifyAuthProof(c.request);
  } finally {
    NOW = FIXED_NOW;
  }
  return { expected: summarize(res), exchanges: exchanges.slice() };
}

async function buildIntentCases() {
  const cases = [];
  const add = async (name, spec) => {
    const intentObj = spec.intentObj ?? mkIntent();
    const signer = spec.signer ?? devA;
    const bytes = await tsCanonical(intentObj);
    const sigs = signAll(signer, bytes);
    const sigPick = spec.sig ?? ((s) => s.compact);
    const signature = typeof sigPick === "string" ? sigPick : sigPick(sigs);
    const shownIntent = spec.shownIntent ?? intentObj;
    const request = {
      user_did: spec.user_did ?? DID,
      intent: shownIntent,
      signature,
      ...(spec.public_key_hex === undefined ? {} : { public_key_hex: spec.public_key_hex }),
    };
    const { expected, exchanges: ex } = await runVerify("intent", {
      request,
      handler: spec.handler,
      now: spec.now,
      api_url: spec.api_url,
    });
    const entry = {
      name,
      now: spec.now ?? FIXED_NOW,
      api_url: spec.api_url ?? API,
      user_did: request.user_did,
      intent_json: JSON.stringify(shownIntent),
      signature: request.signature,
      ...(request.public_key_hex === undefined ? {} : { public_key_hex: request.public_key_hex }),
      exchanges: ex,
      expected,
    };
    if (spec.reason_prefix_only) entry.reason_match = "prefix";
    cases.push(entry);
  };

  const ownerA = record(devA.compressed, "owner", "active");
  const ownerB = record(devB.compressed, "owner", "active");
  const only = (r) => recordsServer([r]);

  await add("latest_owner_compressed", { handler: only(ownerA) });
  await add("latest_owner_uncompressed_key", { handler: only(record(devA.uncompressed, "owner", "active")) });
  await add("second_device_with_key_hint", {
    signer: devB,
    public_key_hex: devB.compressed,
    handler: recordsServer([ownerB, ownerA]),
  });
  await add("second_device_without_key_hint_fails", { signer: devB, handler: recordsServer([ownerB, ownerA]) });
  await add("key_hint_uppercase_0x_prefix", {
    signer: devB,
    public_key_hex: "0x" + devB.compressed.toUpperCase(),
    handler: recordsServer([ownerB, ownerA]),
  });
  await add("key_hint_surrounding_whitespace", {
    signer: devB,
    public_key_hex: "  " + devB.compressed + " \n",
    handler: recordsServer([ownerB, ownerA]),
  });
  await add("key_hint_empty_string_means_latest", { public_key_hex: "", handler: only(ownerA) });
  await add("key_hint_not_on_this_did_404_no_fallback", {
    signer: devC,
    public_key_hex: devC.compressed,
    handler: recordsServer([ownerB, ownerA]),
  });
  await add("latest_revoked_with_timestamp", {
    handler: only(record(devA.compressed, "owner", "revoked", "2026-09-01T00:00:00Z")),
  });
  await add("latest_revoked_no_timestamp", { handler: only(record(devA.compressed, "owner", "revoked", null)) });
  await add("revoked_via_key_hint", {
    signer: devB,
    public_key_hex: devB.compressed,
    handler: recordsServer([record(devB.compressed, "owner", "revoked", "2026-09-02T00:00:00Z"), ownerA]),
  });
  await add("status_unknown_value_is_not_usable", { handler: only(record(devA.compressed, "owner", "pending", null)) });
  await add("status_missing_is_not_usable", {
    handler: () => ok({ public_key_hex: devA.compressed, key_role: "owner" }),
  });
  await add("viewer_key_via_hint", {
    signer: devB,
    public_key_hex: devB.compressed,
    handler: recordsServer([record(devB.compressed, "viewer", "active"), ownerA]),
  });
  await add("manager_key_via_hint", {
    signer: devB,
    public_key_hex: devB.compressed,
    handler: recordsServer([record(devB.compressed, "manager", "active"), ownerA]),
  });
  await add("role_wrong_case_via_hint", {
    signer: devB,
    public_key_hex: devB.compressed,
    handler: recordsServer([record(devB.compressed, "OWNER", "active"), ownerA]),
  });
  await add("key_mismatch_server_returns_other_key", {
    signer: devB,
    public_key_hex: devB.compressed,
    handler: () => ok(record(devC.compressed, "owner", "active")),
  });
  await add("key_match_server_returns_uppercase_0x", {
    signer: devB,
    public_key_hex: devB.compressed,
    handler: () => ok(record("0x" + devB.compressed.toUpperCase(), "owner", "active")),
  });
  await add("server_500", { handler: () => ({ status: 500, body: "{}" }) });
  await add("server_404_latest", { handler: () => notFound() });
  await add("empty_result_null", { handler: () => ok(null) });
  await add("result_without_pubkey", { handler: () => ok({ key_role: "owner", status: "active" }) });
  await add("result_empty_pubkey", { handler: () => ok({ public_key_hex: "", key_role: "owner", status: "active" }) });
  await add("response_not_json", {
    handler: () => ({ status: 200, body: "<html>bad gateway</html>" }),
    reason_prefix_only: true,
  });
  await add("signature_one_bit_flipped", { handler: only(ownerA), sig: (s) => flipLastBit(s.compact) });
  await add("signature_by_other_device_asking_latest", { signer: devB, handler: only(ownerA) });
  await add("intent_display_text_tampered", {
    handler: only(ownerA),
    shownIntent: mkIntent({ display_text: "Send 1000 ADA" }),
  });
  await add("intent_body_amount_tampered", {
    handler: only(ownerA),
    shownIntent: mkIntent({ body: { to: "addr_test1qz...", amount: "9000000", memo: "café ☕" } }),
  });
  await add("intent_key_order_irrelevant", {
    handler: only(ownerA),
    shownIntent: (() => {
      const i = mkIntent();
      return { display_text: i.display_text, timestamp: i.timestamp, nonce: i.nonce, domain: i.domain, body: { memo: i.body.memo, amount: i.body.amount, to: i.body.to }, type: i.type };
    })(),
  });
  await add("intent_unicode_and_numbers", {
    intentObj: mkIntent({ body: { "😀": 1.5, "～": 1e21, é: [0.1, 100.0, -0.0], note: " \u0001" } }),
    handler: only(ownerA),
  });
  await add("timestamp_skew_future_61", {
    intentObj: mkIntent({ timestamp: FIXED_NOW + 61 }),
    handler: only(ownerA),
  });
  await add("timestamp_skew_past_61", {
    intentObj: mkIntent({ timestamp: FIXED_NOW - 61 }),
    handler: only(ownerA),
  });
  await add("timestamp_exactly_60_future_ok", {
    intentObj: mkIntent({ timestamp: FIXED_NOW + 60 }),
    handler: only(ownerA),
  });
  await add("timestamp_exactly_60_past_ok", {
    intentObj: mkIntent({ timestamp: FIXED_NOW - 60 }),
    handler: only(ownerA),
  });
  await add("signature_der", { handler: only(ownerA), sig: (s) => s.der });
  await add("signature_compact_high_s", { handler: only(ownerA), sig: (s) => s.compactHighS });
  await add("signature_der_high_s", { handler: only(ownerA), sig: (s) => s.derHighS });
  await add("signature_0x_prefix", { handler: only(ownerA), sig: (s) => "0x" + s.compact });
  await add("signature_uppercase_hex", { handler: only(ownerA), sig: (s) => s.compact.toUpperCase() });
  await add("signature_odd_length", { handler: only(ownerA), sig: (s) => s.compact.slice(0, -1) });
  await add("signature_non_hex_char", { handler: only(ownerA), sig: (s) => "g" + s.compact.slice(1) });
  await add("signature_empty", { handler: only(ownerA), sig: "" });
  await add("signature_63_bytes", { handler: only(ownerA), sig: (s) => s.compact.slice(0, -2) });
  await add("signature_65_bytes", { handler: only(ownerA), sig: (s) => s.compact + "00" });
  await add("signature_all_zero_64", { handler: only(ownerA), sig: "00".repeat(64) });
  await add("signature_r_s_equal_group_order", {
    handler: only(ownerA),
    sig: p256.CURVE.n.toString(16).padStart(64, "0").repeat(2),
  });
  await add("server_pubkey_odd_length_hex", {
    handler: () => ok(record(devA.compressed.slice(0, -1), "owner", "active")),
  });
  await add("server_pubkey_not_on_curve", {
    handler: () => ok(record("02" + "ff".repeat(32), "owner", "active")),
  });
  await add("server_pubkey_raw_64_bytes_no_prefix", {
    handler: () => ok(record(devA.uncompressed.slice(2), "owner", "active")),
  });
  await add("server_pubkey_hybrid_prefix", {
    handler: () => ok(record("06" + devA.uncompressed.slice(2), "owner", "active")),
  });
  await add("server_pubkey_0x_prefix_valid", {
    handler: () => ok(record("0x" + devA.compressed, "owner", "active")),
  });
  await add("did_needs_percent_encoding", {
    user_did: "did:phoenix:ab c/é?#&=+!~*'()",
    handler: only(ownerA),
  });
  await add("api_url_trailing_slashes_stripped", { api_url: API + "///", handler: only(ownerA) });
  return cases;
}

async function buildAuthCases() {
  const cases = [];
  const ownerA = record(devA.compressed, "owner", "active");
  const only = (r) => recordsServer([r]);
  const add = async (name, spec) => {
    const f = {
      user_did: DID,
      domain: "example.test",
      challenge: "chal-123",
      timestamp: FIXED_NOW,
      ...(spec.fields ?? {}),
    };
    const signer = spec.signer ?? devA;
    const form = spec.form ?? "v1";
    const signedFields = spec.signedFields ?? f;
    const bytes = form === "v1" ? E.encodeRpAuthV1(signedFields) : E.encodeLegacyConcat(signedFields);
    const sigs = signAll(signer, bytes);
    const signature = spec.sig ? spec.sig(sigs) : sigs.compact;
    const request = { ...f, signature };
    const { expected, exchanges: ex } = await runVerify("auth", {
      request,
      handler: spec.handler ?? only(ownerA),
      now: spec.now,
      accept_legacy_envelope: spec.accept_legacy_envelope,
    });
    cases.push({
      name,
      now: spec.now ?? FIXED_NOW,
      ...(spec.accept_legacy_envelope === undefined ? {} : { accept_legacy_envelope: spec.accept_legacy_envelope }),
      request,
      exchanges: ex,
      expected,
    });
  };

  await add("v1_valid", {});
  await add("v1_valid_legacy_disabled", { accept_legacy_envelope: false });
  await add("v1_unicode_fields", { fields: { domain: "日本語.test", challenge: "☕😀" } });
  await add("v1_empty_challenge", { fields: { challenge: "" } });
  await add("legacy_valid_when_accepted", { form: "legacy" });
  await add("legacy_rejected_when_disabled", { form: "legacy", accept_legacy_envelope: false });
  await add("legacy_colon_collision_replayed_at_other_rp", {
    form: "legacy",
    fields: { domain: "c", challenge: "a:b" },
    signedFields: { domain: "b:c", challenge: "a", timestamp: FIXED_NOW },
  });
  await add("v1_colon_collision_not_replayable", {
    fields: { domain: "c", challenge: "a:b" },
    signedFields: { user_did: DID, domain: "b:c", challenge: "a", timestamp: FIXED_NOW },
  });
  await add("wrong_domain", { signedFields: { user_did: DID, domain: "evil.test", challenge: "chal-123", timestamp: FIXED_NOW } });
  await add("wrong_challenge", { signedFields: { user_did: DID, domain: "example.test", challenge: "other", timestamp: FIXED_NOW } });
  await add("wrong_user_did_in_envelope", {
    signedFields: { user_did: "did:phoenix:bbbbbbbbbbbbb:" + "1".repeat(64), domain: "example.test", challenge: "chal-123", timestamp: FIXED_NOW },
  });
  await add("signature_one_bit_flipped", { sig: (s) => flipLastBit(s.compact) });
  await add("signature_by_other_device", { signer: devB });
  await add("signature_der", { sig: (s) => s.der });
  await add("skew_future_61", { fields: { timestamp: FIXED_NOW + 61 } });
  await add("skew_past_61", { fields: { timestamp: FIXED_NOW - 61 } });
  await add("skew_60_ok", { fields: { timestamp: FIXED_NOW - 60 } });
  await add("latest_key_revoked", { handler: only(record(devA.compressed, "owner", "revoked", "2026-09-01T00:00:00Z")) });
  await add("server_404", { handler: () => notFound() });
  await add("only_newest_owner_key_is_used", { signer: devB, handler: recordsServer([record(devB.compressed, "owner", "active"), ownerA]) });
  return cases;
}

// ── 7. app_token vectors ──────────────────────────────────────────────────────
function ed25519Key(label) {
  const priv = sha256Orig(utf8("phoenixkey-sdk-python-vectors/ed25519/" + label));
  const pub = ed25519.getPublicKey(priv);
  return { label, priv, pub, jwk: (kid, extra = {}) => ({ kty: "OKP", crv: "Ed25519", use: "sig", alg: "EdDSA", kid, x: b64url(pub), ...extra }) };
}

const SVC = "did:phoenix:svc:orilife";
const srvK1 = ed25519Key("server-k1");
const srvK2 = ed25519Key("server-k2");

function mintToken({ header, payload, key = srvK1, rawSigningInput, signatureOverride }) {
  const h = b64url(utf8(JSON.stringify(header)));
  const p = b64url(utf8(JSON.stringify(payload)));
  const signingInput = rawSigningInput ?? `${h}.${p}`;
  const sig = signatureOverride ?? b64url(ed25519.sign(utf8(signingInput), key.priv));
  return `${h}.${p}.${sig}`;
}

const basePayload = () => ({
  iss: "https://api.example.test",
  sub: DID,
  aud: SVC,
  iat: FIXED_NOW - 10,
  exp: FIXED_NOW + 300,
  nonce: "n-1",
  key_id: "11111111-1111-4111-8111-111111111111",
  key_role: "owner",
});
const baseHeader = (kid = "k1") => ({ alg: "EdDSA", typ: "JWT", kid });

async function buildTokenCases() {
  const cases = [];
  const jwksOk = (keys) => ({ status: 200, body: JSON.stringify({ keys }) });
  const add = async (name, spec) => {
    const token = spec.token ?? mintToken({ header: spec.header ?? baseHeader(), payload: spec.payload ?? basePayload(), key: spec.key });
    const jwks = spec.jwks ?? jwksOk([srvK1.jwk("k1")]);
    handler = () => jwks;
    exchanges = [];
    NOW = FIXED_NOW;
    const av = new V.AppTokenVerifier({ phoenixkeyApiUrl: API });
    const mode = spec.mode ?? "verify";
    const aud = spec.aud === undefined ? SVC : spec.aud;
    let expected;
    try {
      const claims = mode === "verify" ? await av.verify(token, aud) : await av.verifyWithoutAudience(token);
      expected = { ok: true, claims: JSON.parse(JSON.stringify(claims)) };
    } catch (e) {
      expected = { ok: false, error: { name: e.name, code: e.code ?? null, status: e.status ?? null } };
    }
    cases.push({
      name,
      now: FIXED_NOW,
      token,
      mode,
      expected_aud: mode === "verify" ? aud : null,
      jwks_response: jwks,
      exchanges: exchanges.slice(),
      expected,
    });
  };

  await add("valid_owner", {});
  await add("valid_aud_as_array", { payload: { ...basePayload(), aud: [SVC] } });
  await add("valid_aud_array_second_element", { payload: { ...basePayload(), aud: ["did:phoenix:svc:other", SVC] }, aud: SVC });
  await add("valid_without_audience_mode", { mode: "no-aud", payload: { ...basePayload(), aud: "did:phoenix:svc:anything" } });
  await add("valid_optional_claims_absent", { payload: { iss: "i", sub: "s", aud: SVC, iat: 1, exp: FIXED_NOW + 5 } });
  await add("key_role_absent_becomes_viewer", { payload: (() => { const p = basePayload(); delete p.key_role; return p; })() });
  await add("key_role_unknown_becomes_viewer", { payload: { ...basePayload(), key_role: "superadmin" } });
  await add("key_role_case_and_space_normalised", { payload: { ...basePayload(), key_role: "  OWNER " } });
  await add("key_role_manager", { payload: { ...basePayload(), key_role: "manager" } });
  await add("key_role_not_a_string", { payload: { ...basePayload(), key_role: 7 } });
  await add("float_iat_and_exp", { payload: { ...basePayload(), iat: 1759999990.5, exp: FIXED_NOW + 300.25 } });
  await add("aud_mismatch", { payload: { ...basePayload(), aud: "did:phoenix:svc:other" } });
  await add("aud_missing_in_token", { payload: (() => { const p = basePayload(); delete p.aud; return p; })() });
  await add("expected_aud_empty_string", { aud: "" });
  await add("expired_exactly_now", { payload: { ...basePayload(), exp: FIXED_NOW } });
  await add("expired_past", { payload: { ...basePayload(), exp: FIXED_NOW - 1 } });
  await add("exp_missing", { payload: (() => { const p = basePayload(); delete p.exp; return p; })() });
  await add("exp_is_a_string", { payload: { ...basePayload(), exp: String(FIXED_NOW + 300) } });
  await add("signature_one_bit_flipped", {
    token: (() => {
      const t = mintToken({ header: baseHeader(), payload: basePayload() });
      const [h, p, s] = t.split(".");
      const raw = Buffer.from(s, "base64url");
      raw[raw.length - 1] ^= 1;
      return `${h}.${p}.${b64url(raw)}`;
    })(),
  });
  await add("payload_tampered_after_signing", {
    token: (() => {
      const [h, , s] = mintToken({ header: baseHeader(), payload: basePayload() }).split(".");
      return `${h}.${b64url(utf8(JSON.stringify({ ...basePayload(), key_role: "owner", sub: "did:phoenix:attacker" })))}.${s}`;
    })(),
  });
  await add("signed_by_wrong_key_same_kid", { key: srvK2 });
  await add("kid_unknown", { header: baseHeader("nope") });
  await add("kid_missing", { header: { alg: "EdDSA", typ: "JWT" } });
  await add("kid_empty_string", { header: { alg: "EdDSA", typ: "JWT", kid: "" } });
  await add("alg_none", { header: { alg: "none", typ: "JWT", kid: "k1" } });
  await add("alg_hs256", { header: { alg: "HS256", typ: "JWT", kid: "k1" } });
  await add("alg_lowercase_eddsa", { header: { alg: "eddsa", typ: "JWT", kid: "k1" } });
  await add("jwks_rotation_second_key_selected_by_kid", {
    header: baseHeader("k2"),
    key: srvK2,
    jwks: jwksOk([srvK1.jwk("k1"), srvK2.jwk("k2")]),
  });
  await add("jwks_rotation_first_key_still_selected_by_kid", {
    jwks: jwksOk([srvK2.jwk("k2"), srvK1.jwk("k1")]),
  });
  await add("jwks_rotation_kid_k2_signed_with_k1", {
    header: baseHeader("k2"),
    jwks: jwksOk([srvK1.jwk("k1"), srvK2.jwk("k2")]),
  });
  await add("jwks_wrong_kty", { jwks: jwksOk([{ ...srvK1.jwk("k1"), kty: "RSA" }]) });
  await add("jwks_wrong_crv", { jwks: jwksOk([{ ...srvK1.jwk("k1"), crv: "P-256" }]) });
  await add("jwks_key_x_wrong_length", { jwks: jwksOk([{ ...srvK1.jwk("k1"), x: b64url(srvK1.pub.slice(0, 31)) }]) });
  await add("jwks_empty_keys", { jwks: jwksOk([]) });
  await add("jwks_404", { jwks: { status: 404, body: "{}" } });
  await add("jwks_500", { jwks: { status: 500, body: "oops" } });
  await add("jwks_200_without_keys_array", { jwks: { status: 200, body: JSON.stringify({ keys: "nope" }) } });
  await add("malformed_two_segments", { token: "aaa.bbb" });
  await add("malformed_four_segments", { token: "a.b.c.d" });
  await add("malformed_header_not_json", { token: `${b64url(utf8("not json"))}.${b64url(utf8("{}"))}.${b64url(new Uint8Array(64))}` });
  await add("malformed_payload_not_json", { token: `${b64url(utf8(JSON.stringify(baseHeader())))}.${b64url(utf8("{oops"))}.${b64url(new Uint8Array(64))}` });
  await add("empty_token", { token: "" });
  await add("signature_wrong_length", {
    token: (() => {
      const [h, p] = mintToken({ header: baseHeader(), payload: basePayload() }).split(".");
      return `${h}.${p}.${b64url(new Uint8Array(10))}`;
    })(),
  });
  await add("signature_segment_empty", {
    token: (() => {
      const [h, p] = mintToken({ header: baseHeader(), payload: basePayload() }).split(".");
      return `${h}.${p}.`;
    })(),
  });
  await add("signature_segment_not_base64", {
    token: (() => {
      const [h, p] = mintToken({ header: baseHeader(), payload: basePayload() }).split(".");
      return `${h}.${p}.@@@@`;
    })(),
  });
  return cases;
}

// ── 8. Write ──────────────────────────────────────────────────────────────────
const pkgVersion = (name) => JSON.parse(fs.readFileSync(path.join(ROOT, "node_modules", name, "package.json"), "utf8")).version;
(async () => {
  const keys = {
    p256: Object.fromEntries(
      [devA, devB, devC].map((d) => [d.label, { seed_label: "phoenixkey-sdk-python-vectors/p256/" + d.label, public_compressed_hex: d.compressed, public_uncompressed_hex: d.uncompressed }]),
    ),
    ed25519: Object.fromEntries(
      [srvK1, srvK2].map((k) => [k.label, { seed_label: "phoenixkey-sdk-python-vectors/ed25519/" + k.label, public_hex: hex(k.pub) }]),
    ),
  };
  const out = {
    meta: {
      generator: "python/tests/vectors/generate.cjs",
      description:
        "Expected values are produced by running the TypeScript SDK. Regenerate with `node python/tests/vectors/generate.cjs` and review the diff.",
      fixed_now: FIXED_NOW,
      api_url: API,
      service_did: SVC,
      user_did: DID,
      noble_curves: pkgVersion("@noble/curves"),
      noble_hashes: pkgVersion("@noble/hashes"),
    },
    keys,
    canonical: await buildCanonical(),
    envelope: buildEnvelope(),
    intent: await buildIntentCases(),
    auth_proof: await buildAuthCases(),
    app_token: await buildTokenCases(),
  };
  fs.writeFileSync(OUT, JSON.stringify(out, null, 2) + "\n");
  fs.rmSync(BUILD, { recursive: true, force: true });
  const n = (a) => a.length;
  console.log(
    `wrote ${path.relative(ROOT, OUT)}: canonical=${n(out.canonical)} envelope=${n(out.envelope)} intent=${n(out.intent)} auth_proof=${n(out.auth_proof)} app_token=${n(out.app_token)}`,
  );
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
