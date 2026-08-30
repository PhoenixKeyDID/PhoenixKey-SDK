import { IdentityModule } from "../src/identity";
import { PhoenixKeyError } from "../src/types";

const BASE = "https://api.example.test";

afterEach(() => {
  jest.restoreAllMocks();
});

function mockFetch(impl: (url: string, init: RequestInit) => Promise<Response>) {
  return jest.spyOn(globalThis, "fetch").mockImplementation(impl as typeof fetch);
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

/** Không có phiên — mọi lời gọi ở đây đều là đường công khai. */
const identity = () => new IdentityModule(BASE, () => null);

describe("resolveByUsername", () => {
  it("gọi đúng đường công khai và trả DID", async () => {
    const seen: string[] = [];
    mockFetch(async (url) => {
      seen.push(url);
      return json({
        code: 1000,
        message: "ok",
        result: { username: "an", user_did: "did:phoenix:person:abc" },
      });
    });

    await expect(identity().resolveByUsername("an")).resolves.toEqual({
      username: "an",
      user_did: "did:phoenix:person:abc",
    });
    expect(seen[0]).toBe(`${BASE}/identity/by-username/an`);
  });

  it("mã hoá tên trước khi ghép vào đường dẫn", async () => {
    // Tên có dấu và có ký tự đổi nghĩa đường dẫn. Ghép thô thì `a/b` thành hai
    // đoạn đường và lời gọi đi tới một endpoint khác hẳn — hỏng lặng lẽ, không
    // báo lỗi gì.
    const seen: string[] = [];
    mockFetch(async (url) => {
      seen.push(url);
      return json({ code: 1000, result: { username: "x", user_did: "did:phoenix:person:x" } });
    });

    await identity().resolveByUsername("chị oanh/../admin");
    expect(seen[0]).toBe(
      `${BASE}/identity/by-username/ch%E1%BB%8B%20oanh%2F..%2Fadmin`,
    );
    expect(seen[0]).not.toContain("/admin");
  });

  it("ném user_not_found khi chưa ai giữ tên", async () => {
    mockFetch(async () => json({ code: 2001, message: "không tồn tại" }, 404));

    await expect(identity().resolveByUsername("chưa-ai-lấy")).rejects.toMatchObject({
      code: "user_not_found",
      status: 404,
    });
  });
});

describe("lookupUsername", () => {
  it("trả null khi backend nói rõ là không tìm thấy", async () => {
    mockFetch(async () => json({ code: 2001, message: "không tồn tại" }, 404));
    await expect(identity().lookupUsername("chưa-ai-lấy")).resolves.toBeNull();
  });

  it("trả kết quả như thường khi tên có chủ", async () => {
    mockFetch(async () =>
      json({ code: 1000, result: { username: "an", user_did: "did:phoenix:person:abc" } }),
    );
    await expect(identity().lookupUsername("an")).resolves.toEqual({
      username: "an",
      user_did: "did:phoenix:person:abc",
    });
  });

  // Đây là vế load-bearing của cả hàm. Nuốt rộng tay thì mạng hỏng cũng thành
  // "không có tên này", và màn hình sẽ mời người dùng đặt một cái tên mà thật ra
  // đang có chủ — sai theo hướng nguy hiểm nhất.
  it.each([
    ["mạng hỏng", 0, "network_error", async () => { throw new TypeError("failed to fetch"); }],
    ["5xx", 500, "http_500", async () => json({ message: "boom" }, 500)],
    ["hết hạn phiên", 401, "session_expired", async () => json({ code: 1302 }, 401)],
  ])("KHÔNG nuốt lỗi khác: %s", async (_label, status, code, impl) => {
    mockFetch(impl as never);

    const p = identity().lookupUsername("an");
    await expect(p).rejects.toBeInstanceOf(PhoenixKeyError);
    await expect(p).rejects.toMatchObject({ code, status });
  });

  it("nuốt ĐÚNG một mã, không nuốt theo trạng thái HTTP", async () => {
    // 404 mà mã khác 2001 thì vẫn phải ném. Bắt theo `status === 404` là cái bẫy
    // dễ rơi vào nhất khi ai đó viết lại hàm này cho "gọn".
    mockFetch(async () => json({ code: 2002, message: "did không có" }, 404));

    await expect(identity().lookupUsername("an")).rejects.toMatchObject({
      code: "user_did_not_found",
      status: 404,
    });
  });
});
