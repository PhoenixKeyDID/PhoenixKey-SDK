/**
 * `PoolModule` — pool + uỷ quyền stake, ba đường CHỈ ĐỌC.
 *
 * Ba điều được chốt ở đây:
 *  1. đường dẫn + tham số truy vấn đúng tuyến `PoolController`;
 *  2. trang bắt đầu từ 1 (Blockfrost), không phải 0;
 *  3. số dư giữ nguyên CHUỖI — `BigInt` cộng được, `Number` thì mất chữ số.
 */

import { PoolModule } from "../src/pool";

const BASE = "https://api.example.test/api/v1";
const POOL_ID = "pool1abcdefghijklmnopqrstuvwxyz0123456789abcdefghij";
const STAKE = "stake_test1uz0000000000000000000000000000000000000000000000";

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

function mockErr(code: number, status: number, message = "boom") {
  calls.length = 0;
  return jest.spyOn(globalThis, "fetch").mockImplementation((async (url: string) => {
    calls.push(String(url));
    return new Response(JSON.stringify({ code, message }), {
      status,
      headers: { "Content-Type": "application/json" },
    });
  }) as unknown as typeof fetch);
}

const mod = () => new PoolModule(BASE);

afterEach(() => {
  jest.restoreAllMocks();
});

describe("PoolModule — tuyến đường", () => {
  it("listPools mặc định page=1, KHÔNG page=0", async () => {
    mockOk({ pool_ids: [], page: 1, count: 0 });
    await mod().listPools();
    expect(calls[0]).toBe(`${BASE}/pools?page=1`);
    // Blockfrost đánh số trang từ 1; gửi 0 là mất im lặng cả trang đầu.
    expect(calls[0]).not.toContain("page=0");
  });

  it("size chỉ xuất hiện khi bên gọi truyền", async () => {
    mockOk({ pool_ids: [], page: 2, count: 0 });
    const m = mod();
    await m.listPools(2);
    await m.listPools(2, 20);
    expect(calls).toEqual([`${BASE}/pools?page=2`, `${BASE}/pools?page=2&size=20`]);
  });

  it("getPool + getDelegationStatus đi đúng đường, tham số được mã hoá", async () => {
    mockOk({});
    const m = mod();
    await m.getPool(POOL_ID);
    await m.getDelegationStatus(STAKE);
    expect(calls).toEqual([
      `${BASE}/pools/${POOL_ID}`,
      `${BASE}/delegation/status/${STAKE}`,
    ]);
  });

  it("id chứa ký tự cần mã hoá không cắt được đường dẫn", async () => {
    mockOk({});
    await mod().getPool("pool1/../../admin");
    expect(calls[0]).toBe(`${BASE}/pools/pool1%2F..%2F..%2Fadmin`);
    expect(calls[0]).not.toContain("/pools/pool1/..");
  });

  it("ba đường KHÔNG gắn Authorization — chúng là dữ liệu công khai", async () => {
    const f = mockOk({});
    const m = mod();
    await m.listPools();
    await m.getPool(POOL_ID);
    await m.getDelegationStatus(STAKE);
    for (const call of f.mock.calls) {
      const headers = (call[1] as RequestInit).headers as Record<string, string>;
      expect(headers.Authorization).toBeUndefined();
    }
  });
});

describe("PoolModule — số dư là chuỗi", () => {
  it("live_stake vượt Number.MAX_SAFE_INTEGER vẫn nguyên từng chữ số", async () => {
    // 45 tỷ ADA quy ra lovelace — lớn hơn 2^53.
    const huge = "45000000000000000";
    mockOk({
      pool_id: POOL_ID,
      hex: "ab",
      blocks_minted: 12345,
      live_stake: huge,
      live_saturation: 0.85,
      active_stake: huge,
      declared_pledge: "500000000000",
      live_pledge: "500000000000",
      margin_cost: 0.03,
      fixed_cost: "340000000",
      reward_account: "stake1...",
      ticker: null,
      name: null,
      description: null,
      homepage: null,
    });
    const res = await mod().getPool(POOL_ID);

    expect(typeof res.live_stake).toBe("string");
    expect(res.live_stake).toBe(huge);
    expect(Number.isSafeInteger(Number(res.live_stake))).toBe(false);
    // Cách cộng đúng.
    expect((BigInt(res.live_stake) + BigInt(res.active_stake)).toString()).toBe(
      "90000000000000000",
    );
  });

  it("margin_cost là phân số 0..1, không phải phần trăm", async () => {
    mockOk({ pool_id: POOL_ID, margin_cost: 0.03 });
    const res = await mod().getPool(POOL_ID);
    expect(res.margin_cost).toBe(0.03);
    expect(res.margin_cost).toBeLessThanOrEqual(1);
  });

  it("bốn trường siêu dữ liệu null KHÔNG có nghĩa pool không tồn tại", async () => {
    mockOk({
      pool_id: POOL_ID,
      ticker: null,
      name: null,
      description: null,
      homepage: null,
    });
    const res = await mod().getPool(POOL_ID);
    expect(res.pool_id).toBe(POOL_ID);
    expect(res.ticker).toBeNull();
  });
});

describe("PoolModule — trạng thái uỷ quyền", () => {
  it("tài khoản chưa kích hoạt là câu trả lời BÌNH THƯỜNG, không phải lỗi", async () => {
    mockOk({
      stake_address: STAKE,
      active: false,
      pool_id: null,
      controlled_amount: "0",
      rewards_sum: "0",
      withdrawable_amount: "0",
    });
    const res = await mod().getDelegationStatus(STAKE);
    expect(res.active).toBe(false);
    expect(res.pool_id).toBeNull();
    expect(res.controlled_amount).toBe("0");
  });

  it("1370 → 'pool_not_found', phân biệt được với lỗi cổng Blockfrost", async () => {
    mockErr(1370, 404, "Pool not found");
    await expect(mod().getPool(POOL_ID)).rejects.toMatchObject({
      code: "pool_not_found",
      status: 404,
    });

    // Blockfrost hỏng phía máy chủ vọng về là lỗi cổng, KHÔNG phải "không có
    // pool" — hai thứ này hiện cho người dùng hai câu khác hẳn nhau.
    jest.restoreAllMocks();
    mockErr(5102, 502, "Blockfrost upstream failed");
    await expect(mod().getPool(POOL_ID)).rejects.toMatchObject({
      code: "cardano_resolve_failed",
      status: 502,
    });
  });
});
