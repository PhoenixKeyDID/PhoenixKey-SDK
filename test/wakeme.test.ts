import { WakemeModule, ActivationModule } from "../src/wakeme";
import { PhoenixKeyError } from "../src/types";

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

// Tên describe cũ là "retired VND/Genie flow STILL ANSWERS on /activation", và
// hai bài dưới nó khẳng định `initiate` gọi đúng `/activation/initiate`. Đường
// đó không còn handler nào từ 2026-09-03 ⇒ 404. Nên bộ test này pin đúng hành
// vi hiện tại nhưng TÊN của nó khai một điều sai, và một bài xanh dưới một tên
// sai là chỗ người đọc sau lấy làm bằng chứng.
describe("WakemeModule — luồng VND/Genie đã bỏ: ném ngay, KHÔNG đi mạng", () => {
  // Điểm chính của các bài này KHÔNG phải "nó ném" — mà là "nó không gửi gì".
  // Một bài chỉ kiểm `rejects` sẽ xanh y nguyên với mã cũ, vì mã cũ cũng ném
  // (404 từ fetcher). Nên phép đo thật là `calls` rỗng.
  const RETIRED: Array<[string, (m: WakemeModule) => unknown]> = [
    ["initiate", (m) => m.initiate("addr_test1abc")],
    ["getStatus", (m) => m.getStatus("a-1")],
    // Handler hợp lệ nhưng không bao giờ chạy: `openEventStream` ném ĐỒNG BỘ
    // trước khi mở luồng. Truyền `{}` thì gọn hơn, nhưng `SseHandlers` đòi
    // `onMessage`, nên `{}` là một bài kiểm không biên dịch được — nó chỉ xanh
    // hồi `test/**` chưa ai kiểm kiểu.
    ["openEventStream", (m) => m.openEventStream("a-1", { onMessage: () => {} })],
    ["cancel", (m) => m.cancel("a-1")],
    ["mockConfirmPayment", (m) => m.mockConfirmPayment("a-1", "admin")],
    ["submitTx", (m) => m.submitTx("a-1", "beef")],
  ];

  for (const [name, call] of RETIRED) {
    it(`${name}() ném flow_retired và không gửi request nào`, async () => {
      mockOk();
      const m = mod();
      let err: unknown;
      try {
        // `await` bao được cả hai: phương thức async (trả promise bị reject) và
        // `openEventStream` (ném đồng bộ). Nếu không bọc chung thì bài cho SSE
        // phải viết khác, và cái khác đó là chỗ dễ viết thành "chỉ kiểm ném".
        await call(m);
      } catch (e) {
        err = e;
      }
      expect(err).toBeInstanceOf(PhoenixKeyError);
      const pk = err as PhoenixKeyError;
      expect(pk.code).toBe("flow_retired");
      // status 0 = chưa từng có phản hồi HTTP. KHÔNG phải 404 (đó là mã cũ
      // nhận được SAU khi đã đi mạng) và không phải 410 (không ai gửi nó).
      expect(pk.status).toBe(0);
      expect(pk.userMessageKey).toBe("errors.flow_retired");
      // Lời nhắn phải chỉ được đường ra, không chỉ nói "đã bỏ".
      expect(pk.message).toContain("2026-09-03");
      expect(pk.message).toContain("VND-GENIE-REMOVAL.md");
      // ĐÂY là phép đo. Mã cũ làm dòng này đỏ.
      expect(calls).toEqual([]);
    });
  }

  it("vẫn CÒN trên prototype — mã người dùng phải biên dịch được", () => {
    // #9 xin "giữ alias một vòng release để không vỡ consumer đột ngột". Ném
    // nhanh vẫn thoả điều đó; XOÁ thì không. Bài này là thứ phân biệt hai việc.
    const m = mod();
    for (const [name] of RETIRED) {
      expect(typeof (m as unknown as Record<string, unknown>)[name]).toBe("function");
    }
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
