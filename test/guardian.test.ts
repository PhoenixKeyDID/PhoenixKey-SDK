/**
 * `GuardianModule` — mạng lưới người bảo hộ khôi phục.
 *
 * Bốn điều được chốt ở đây:
 *  1. ba đường đi đúng tuyến `/guardians/*` của `GuardianController`;
 *  2. thân yêu cầu đi SNAKE_CASE — máy chủ đọc `op_seq`, không đọc `opSeq`;
 *  3. `list()` bắt buộc thẻ phiên và KHÔNG đi mạng khi chưa đăng nhập;
 *  4. 4003 là "tự đặt mình làm người bảo hộ", KHÔNG phải lỗi chữ ký.
 */

import { GuardianModule } from "../src/guardian";
import { PhoenixKeyError } from "../src/types";

const BASE = "https://api.example.test/api/v1";
const TOKEN = "session-token";
const USER_DID = "did:phoenix:aaaaaaahl4nn6:" + "ab".repeat(32);
const GUARDIAN_DID = "did:phoenix:aaaaaaahomxng:" + "cd".repeat(32);

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

function mod(token: string | null = TOKEN) {
  return new GuardianModule(BASE, () => token);
}

const PARAMS = {
  userDid: USER_DID,
  guardianDid: GUARDIAN_DID,
  proofSignature: "3044deadbeef",
  nonce: "n-1",
  opSeq: 7,
};

afterEach(() => {
  jest.restoreAllMocks();
});

describe("GuardianModule — tuyến đường", () => {
  it("add hits /guardians/add", async () => {
    mockOk({ guardian_count: 3 });
    await mod().add(PARAMS);
    expect(calls[0]).toBe(`${BASE}/guardians/add`);
  });

  it("remove hits /guardians/remove", async () => {
    mockOk({ guardian_count: 2 });
    await mod().remove(PARAMS);
    expect(calls[0]).toBe(`${BASE}/guardians/remove`);
  });

  it("list hits /guardians/{userDid} và DID được mã hoá vào đường dẫn", async () => {
    mockOk({ guardians: [], count: 0 });
    await mod().list(USER_DID);
    expect(calls[0]).toBe(`${BASE}/guardians/${encodeURIComponent(USER_DID)}`);
    // Dấu hai chấm trong DID phải được mã hoá, không được để trần cắt đường dẫn.
    expect(calls[0]).toContain("did%3Aphoenix%3A");
  });
});

describe("GuardianModule — thân yêu cầu đi SNAKE_CASE", () => {
  it("add gửi đúng năm trường snake_case, không rò camelCase", async () => {
    const f = mockOk({ guardian_count: 3 });
    await mod().add(PARAMS);
    const init = f.mock.calls[0][1] as RequestInit;
    const body = JSON.parse(String(init.body));

    expect(body).toEqual({
      user_did: USER_DID,
      guardian_did: GUARDIAN_DID,
      proof_signature: "3044deadbeef",
      nonce: "n-1",
      op_seq: 7,
    });
    // Máy chủ đọc SNAKE_CASE toàn cục — một trường camelCase lọt qua là trường
    // đó bị bỏ qua lặng lẽ, và `op_seq` thiếu thì lượt gọi hỏng ở tầng kiểm tra.
    expect(Object.keys(body)).not.toContain("opSeq");
    expect(Object.keys(body)).not.toContain("proofSignature");
  });

  it("remove gửi cùng hình dạng thân như add", async () => {
    const f = mockOk({ guardian_count: 2 });
    await mod().remove(PARAMS);
    const init = f.mock.calls[0][1] as RequestInit;
    expect(JSON.parse(String(init.body)).op_seq).toBe(7);
  });

  it("add/remove KHÔNG gắn thẻ phiên — thẩm quyền đến từ chữ ký, không từ phiên", async () => {
    const f = mockOk({ guardian_count: 3 });
    await mod().add(PARAMS);
    const init = f.mock.calls[0][1] as RequestInit;
    const headers = init.headers as Record<string, string>;
    expect(headers.Authorization).toBeUndefined();
  });

  it("chạy được cả khi chưa đăng nhập — add không đòi thẻ phiên", async () => {
    mockOk({ guardian_count: 3 });
    await expect(mod(null).add(PARAMS)).resolves.toEqual({ guardian_count: 3 });
    expect(calls).toHaveLength(1);
  });
});

describe("GuardianModule — list đòi thẻ phiên", () => {
  it("gắn Bearer khi đã đăng nhập", async () => {
    const f = mockOk({ guardians: [], count: 0 });
    await mod().list(USER_DID);
    const init = f.mock.calls[0][1] as RequestInit;
    expect((init.headers as Record<string, string>).Authorization).toBe(
      `Bearer ${TOKEN}`,
    );
  });

  it("chưa đăng nhập thì ném NGAY, không tiêu một lượt đi mạng", async () => {
    mockOk();
    await expect(mod(null).list(USER_DID)).rejects.toThrow("No session token");
    expect(calls).toHaveLength(0);
  });

  it("trả nguyên danh sách + đếm", async () => {
    mockOk({
      guardians: [
        {
          guardian_did: GUARDIAN_DID,
          status: "active",
          created_at: "2026-08-01T10:00:00Z",
        },
      ],
      count: 1,
    });
    const res = await mod().list(USER_DID);
    expect(res.count).toBe(1);
    expect(res.guardians[0].guardian_did).toBe(GUARDIAN_DID);
    // Chữ ký của người khác không bao giờ được có mặt ở phía đọc.
    expect(Object.keys(res.guardians[0])).not.toContain("proof_signature");
  });
});

describe("GuardianModule — mã lỗi phân biệt được", () => {
  it("4003 là 'tự đặt mình làm người bảo hộ', KHÔNG phải lỗi chữ ký", async () => {
    mockErr(4003, 400, "User cannot be their own guardian");
    const err = await mod()
      .add({ ...PARAMS, guardianDid: USER_DID })
      .catch((e) => e as PhoenixKeyError);

    expect(err).toBeInstanceOf(PhoenixKeyError);
    expect((err as PhoenixKeyError).code).toBe("guardian_self_not_allowed");
    // Đây là điểm của cả bài: nhãn cũ nói sai bản chất, và người tích hợp bắt
    // theo nhãn cũ sẽ bảo người dùng "ký lại" cho một lỗi không liên quan tới ký.
    expect((err as PhoenixKeyError).code).not.toBe("guardian_signature_invalid");
  });

  it("1403 mới là lỗi chữ ký của luồng guardian", async () => {
    mockErr(1403, 403, "Invalid signature");
    await expect(mod().add(PARAMS)).rejects.toMatchObject({
      code: "signature_invalid",
      status: 403,
    });
  });

  it("3009 OP_SEQ_REPLAY → 'op_seq_replay' (mốc nước dùng chung với /keys/*)", async () => {
    mockErr(3009, 409, "opSeq must be greater than the current watermark");
    await expect(mod().remove(PARAMS)).rejects.toMatchObject({
      code: "op_seq_replay",
      status: 409,
    });
  });

  it("4001 / 4002 giữ nguyên nhãn", async () => {
    mockErr(4002, 409, "Guardian already exists for this user");
    await expect(mod().add(PARAMS)).rejects.toMatchObject({
      code: "guardian_already_exists",
    });
  });

  it("list của DID khác chủ phiên → 'unauthorized' (1304)", async () => {
    mockErr(1304, 401, "Guardian list chỉ trả cho caller");
    await expect(mod().list(GUARDIAN_DID)).rejects.toMatchObject({
      code: "unauthorized",
    });
  });
});
