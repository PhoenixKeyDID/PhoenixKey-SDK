/**
 * Bàn giao phiên đăng nhập cho trang web bên thứ ba — `src/sso.ts`.
 *
 * Mỗi mô tả dưới đây gác một BẤT BIẾN, không gác một cái tên hay một vị trí.
 * Bảng đột biến nằm ở cuối tệp: gỡ đúng một mệnh đề trong mã ⇒ đúng bài ở đây
 * đỏ, và không bài nào khác đỏ theo.
 */

import {
  buildLoginUrl,
  consumeHandoff,
  createHandoffState,
  readHandoff,
  stripHandoffFragment,
  DEFAULT_LOGIN_URL,
  FORBIDDEN_HANDOFF_KEYS,
  HANDOFF_KEY_APP_TOKEN,
  NONCE_MAX_LENGTH,
} from "../src/sso";
import { PhoenixKeyError } from "../src/types";

const CB = "https://app.doitac.com/callback";
const APP_TOKEN = "APP.TOKEN.NGAN-HAN-15-PHUT";

/**
 * Giá trị thẻ phiên dùng xuyên suốt. Bài kiểm giá trị (không phải bài kiểm tên
 * khoá) sẽ tìm ĐÚNG chuỗi này trong mọi thứ đi ra.
 */
const SESSION_TOKEN = "SESSION.TOKEN.TOAN-QUYEN-24-GIO-KHONG-DUOC-RA-KHOI-TRANG-DANG-NHAP";

function frag(url: string, pairs: Record<string, string>): string {
  const p = new URLSearchParams(pairs);
  return `${url}#${p.toString()}`;
}

// ─── Bước 1: rời trang của bạn ────────────────────────────────────────────────

describe("buildLoginUrl", () => {
  it("đặt redirect_uri + state ở CHUỖI TRUY VẤN, trỏ đúng trang đăng nhập", () => {
    const href = buildLoginUrl({ redirectUri: CB, state: "abc123" });
    const u = new URL(href);

    expect(`${u.origin}${u.pathname}`).toBe(DEFAULT_LOGIN_URL);
    expect(u.searchParams.get("redirect_uri")).toBe(CB);
    expect(u.searchParams.get("state")).toBe("abc123");
    // Chiều đi CHƯA có thẻ nào tồn tại — không được có gì ở fragment.
    expect(u.hash).toBe("");
  });

  it("giữ NGUYÊN VĂN redirect_uri, kể cả dấu / cuối — máy chủ so chuỗi, không chuẩn hoá", () => {
    const withTrailingSlash = "https://app.doitac.com/callback/";
    const u = new URL(buildLoginUrl({ redirectUri: withTrailingSlash }));
    expect(u.searchParams.get("redirect_uri")).toBe(withTrailingSlash);
    expect(u.searchParams.get("redirect_uri")).not.toBe(CB);
  });

  it("bỏ state thì không có tham số state rỗng trôi vào URL", () => {
    const u = new URL(buildLoginUrl({ redirectUri: CB }));
    expect(u.searchParams.has("state")).toBe(false);
  });

  it("giao thức ngoài http/https bị từ chối", () => {
    for (const badScheme of ["javascript:alert(1)", "data:text/html,x", "file:///etc/passwd"]) {
      expect(() => buildLoginUrl({ redirectUri: badScheme })).toThrow(PhoenixKeyError);
    }
  });

  it("redirectUri không parse được thì ném, không lặng lẽ dựng URL cụt", () => {
    expect(() => buildLoginUrl({ redirectUri: "/callback" })).toThrow(PhoenixKeyError);
  });

  it("trang đăng nhập tự dựng được (máy cục bộ, môi trường thử)", () => {
    const u = new URL(
      buildLoginUrl({ redirectUri: "http://localhost:3000/cb", loginUrl: "http://localhost:3001/login" }),
    );
    expect(u.origin).toBe("http://localhost:3001");
  });
});

describe("createHandoffState", () => {
  it("dùng nguồn ngẫu nhiên mật mã, không phải Math.random", () => {
    const spy = jest.spyOn(globalThis.crypto, "getRandomValues");
    createHandoffState();
    expect(spy).toHaveBeenCalled();
    spy.mockRestore();
  });

  it("mỗi lượt một giá trị khác nhau", () => {
    const n = new Set(Array.from({ length: 50 }, () => createHandoffState()));
    expect(n.size).toBe(50);
  });

  it("mặc định vừa dưới trần nonce, nên trang đăng nhập ràng được vào thẻ", () => {
    const s = createHandoffState();
    expect(s.length).toBeLessThanOrEqual(NONCE_MAX_LENGTH);
    // …và vẫn đủ dài để không đoán được: 32 byte → 43 ký tự base64url.
    expect(s.length).toBeGreaterThanOrEqual(43);
  });

  it("là base64url an-toàn-cho-URL — không +, /, hay =", () => {
    expect(createHandoffState()).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("không có crypto thì NÉM, không lặng lẽ hạ cấp", () => {
    const that = globalThis as { crypto?: Crypto };
    const real = that.crypto;
    // @ts-expect-error — cố tình gỡ để dựng ca hỏng
    delete that.crypto;
    try {
      expect(() => createHandoffState()).toThrow(/getRandomValues/);
    } finally {
      that.crypto = real;
    }
  });
});

// ─── Bước 3: nhận ở trang callback ────────────────────────────────────────────

describe("readHandoff — chỗ đọc", () => {
  it("đọc app_token + user_did + state từ fragment", () => {
    const out = readHandoff(
      frag(CB, { app_token: APP_TOKEN, user_did: "did:phoenix:a:b", state: "s1" }),
    );
    expect(out).toEqual({
      appToken: APP_TOKEN,
      userDid: "did:phoenix:a:b",
      state: "s1",
    });
  });

  it("không có fragment ⇒ null, KHÔNG ném (người dùng vào thẳng trang)", () => {
    expect(readHandoff(CB)).toBeNull();
    expect(readHandoff(`${CB}#`)).toBeNull();
  });

  it("fragment có thứ khác nhưng không có app_token ⇒ null", () => {
    expect(readHandoff(frag(CB, { state: "s1" }))).toBeNull();
  });

  it("giữ nguyên path + query của trang callback", () => {
    const out = readHandoff(frag(`${CB}?next=%2Fbang-dieu-khien`, { app_token: APP_TOKEN }));
    expect(out?.appToken).toBe(APP_TOKEN);
  });
});

describe("readHandoff — thẻ CHỈ được đọc từ fragment, không bao giờ từ query", () => {
  it("app_token nằm ở chuỗi truy vấn KHÔNG được nhận", () => {
    // Query đi vào `Referer`, vào log proxy, vào log truy cập. Nhận ở đây là
    // hợp thức hoá một chỗ rò.
    const out = readHandoff(`${CB}?app_token=${encodeURIComponent(APP_TOKEN)}`);
    expect(out).toBeNull();
  });

  it("fragment CÓ mặt nhưng không mang thẻ, query mang thẻ ⇒ vẫn null", () => {
    // Ca này là ca thật sự gác: URL không fragment thì `readHandoff` đã trả null
    // ở ngay dòng đầu, nên nó KHÔNG chứng minh được gì về việc có đọc query hay
    // không. Phải có fragment để đi qua cổng đó, rồi mới đo được nguồn của thẻ.
    // (Đột biến "thêm `?? url.searchParams.get(...)`" chạy qua bài kia mà không
    // đỏ — đo được 2026-09-08.)
    const out = readHandoff(`${CB}?app_token=${encodeURIComponent(APP_TOKEN)}#state=s1`);
    expect(out).toBeNull();
  });

  it("query mang thẻ, fragment mang thẻ KHÁC ⇒ lấy đúng cái ở fragment", () => {
    const FROM_QUERY = "THE.O.QUERY.KHONG-DUOC-DUNG";
    const out = readHandoff(
      `${CB}?app_token=${encodeURIComponent(FROM_QUERY)}#app_token=${encodeURIComponent(APP_TOKEN)}`,
    );
    expect(out?.appToken).toBe(APP_TOKEN);
    expect(out?.appToken).not.toBe(FROM_QUERY);
    expect(JSON.stringify(out)).not.toContain(FROM_QUERY);
  });
});

describe("readHandoff — thẻ rộng hơn app_token thì TỪ CHỐI (hỏng-đóng)", () => {
  // Bài GÁC GIÁ TRỊ, không chỉ gác tên khoá: chuỗi thẻ phiên thật phải không
  // xuất hiện ở BẤT KỲ đâu trong thứ đi ra.
  it("session_token trong fragment ⇒ ném, và giá trị đó không rò ra kết quả", () => {
    const url = frag(CB, { app_token: APP_TOKEN, session_token: SESSION_TOKEN });

    let thrown: unknown;
    try {
      readHandoff(url);
    } catch (e) {
      thrown = e;
    }

    expect(thrown).toBeInstanceOf(PhoenixKeyError);
    expect((thrown as PhoenixKeyError).code).toBe("forbidden_token_in_handoff");
    // Không có nhánh nào trả về thẻ trong khi fragment còn mang session_token…
    expect(() => readHandoff(url)).toThrow();
    // …và bản thân lời nhắn lỗi cũng không chép lại giá trị bí mật vào log.
    expect((thrown as PhoenixKeyError).message).not.toContain(SESSION_TOKEN);
  });

  it("cả ba loại thẻ rộng đều bị từ chối, kể cả khi KHÔNG kèm app_token", () => {
    for (const key of FORBIDDEN_HANDOFF_KEYS) {
      expect(() => readHandoff(frag(CB, { [key]: SESSION_TOKEN }))).toThrow(
        PhoenixKeyError,
      );
    }
    // Chốt danh sách: thiếu một cái là hở một đường.
    expect([...FORBIDDEN_HANDOFF_KEYS].sort()).toEqual([
      "linked_device_token",
      "session_token",
      "temp_token",
    ]);
  });
});

describe("readHandoff — đối chiếu state", () => {
  it("state khớp ⇒ qua", () => {
    const out = readHandoff(frag(CB, { app_token: APP_TOKEN, state: "s1" }), {
      expectedState: "s1",
    });
    expect(out?.appToken).toBe(APP_TOKEN);
  });

  it("state lệch ⇒ ném, và KHÔNG trả thẻ về", () => {
    const url = frag(CB, { app_token: APP_TOKEN, state: "cua-ke-tan-cong" });
    let out: unknown;
    expect(() => {
      out = readHandoff(url, { expectedState: "s1" });
    }).toThrow(PhoenixKeyError);
    expect(out).toBeUndefined();
  });

  it("chờ state mà fragment không có state ⇒ ném (không coi thiếu là khớp)", () => {
    expect(() =>
      readHandoff(frag(CB, { app_token: APP_TOKEN }), { expectedState: "s1" }),
    ).toThrow(PhoenixKeyError);
  });

  it("không truyền expectedState thì không đối chiếu — trách nhiệm chuyển sang người gọi", () => {
    const out = readHandoff(frag(CB, { app_token: APP_TOKEN, state: "bat-ky" }));
    expect(out?.state).toBe("bat-ky");
  });
});

// ─── Xoá khỏi thanh địa chỉ ───────────────────────────────────────────────────

describe("stripHandoffFragment", () => {
  it("bỏ fragment, giữ path + query, không để lại dấu # trơ", () => {
    const sach = stripHandoffFragment(frag(`${CB}?next=%2Fx`, { app_token: APP_TOKEN }));
    expect(sach).toBe(`${CB}?next=%2Fx`);
    expect(sach).not.toContain("#");
    expect(sach).not.toContain(APP_TOKEN);
  });

  it("URL vốn không có fragment thì không đổi", () => {
    expect(stripHandoffFragment(CB)).toBe(CB);
  });
});

describe("consumeHandoff — đọc rồi XOÁ khỏi lịch sử", () => {
  const that = globalThis as Record<string, unknown>;
  let saved: { location?: unknown; history?: unknown };

  /** Dựng một trình duyệt giả tối thiểu, ghi lại mọi lượt replaceState. */
  function mockBrowser(href: string) {
    const calls: string[] = [];
    that.location = { href };
    that.history = {
      replaceState: (_d: unknown, _t: string, u: string) => {
        calls.push(u);
        (that.location as { href: string }).href = u;
      },
    };
    return calls;
  }

  beforeEach(() => {
    saved = { location: that.location, history: that.history };
  });
  afterEach(() => {
    that.location = saved.location;
    that.history = saved.history;
  });

  it("trả về lượt bàn giao VÀ gỡ thẻ khỏi URL", () => {
    const calls = mockBrowser(frag(`${CB}?next=%2Fx`, { app_token: APP_TOKEN, state: "s1" }));

    const out = consumeHandoff({ expectedState: "s1" });

    expect(out?.appToken).toBe(APP_TOKEN);
    expect(calls).toHaveLength(1);
    // Bài GÁC GIÁ TRỊ: chuỗi thẻ phải biến mất khỏi URL còn lại.
    expect(calls[0]).not.toContain(APP_TOKEN);
    expect(calls[0]).not.toContain(HANDOFF_KEY_APP_TOKEN);
    // …mà phần trang của bạn cần thì còn nguyên.
    expect(calls[0]).toBe(`${CB}?next=%2Fx`);
  });

  it("dùng replaceState chứ KHÔNG thêm mục lịch sử mới", () => {
    // pushState không được phép có mặt: nó để lại mục cũ — mục còn mang thẻ —
    // cho nút Quay lại.
    const calls: string[] = [];
    that.location = { href: frag(CB, { app_token: APP_TOKEN }) };
    const pushState = jest.fn();
    that.history = {
      replaceState: (_d: unknown, _t: string, u: string) => calls.push(u),
      pushState,
    };

    consumeHandoff();

    expect(calls).toHaveLength(1);
    expect(pushState).not.toHaveBeenCalled();
  });

  it("lượt bàn giao BỊ TỪ CHỐI vẫn được dọn khỏi thanh địa chỉ", () => {
    const calls = mockBrowser(
      frag(CB, { app_token: APP_TOKEN, session_token: SESSION_TOKEN }),
    );

    expect(() => consumeHandoff()).toThrow(PhoenixKeyError);

    // Ném sớm không phải cớ để thẻ nằm lại trong lịch sử trình duyệt.
    expect(calls).toHaveLength(1);
    expect(calls[0]).not.toContain(SESSION_TOKEN);
    expect(calls[0]).not.toContain(APP_TOKEN);
  });

  it("không có bàn giao thì không ghi gì vào lịch sử", () => {
    const calls = mockBrowser(CB);
    expect(consumeHandoff()).toBeNull();
    expect(calls).toHaveLength(0);
  });

  it("SSR (không có location) ⇒ null, không nổ", () => {
    delete that.location;
    delete that.history;
    expect(consumeHandoff()).toBeNull();
  });
});

// ─── Vòng khép kín với thứ Frontend thật sự ghi ra ────────────────────────────

describe("khớp hợp đồng với buildHandoffHref của Frontend", () => {
  /**
   * Bản sao NGUYÊN VĂN cách `PhoenixKey-Frontend/src/lib/redirect.ts`
   * (`buildHandoffHref`) dựng fragment, tính tới 2026-09-08. Chép lại ở đây để
   * bài kiểm này đỏ nếu hai bên trôi khỏi nhau — hai kho khác nhau nên không có
   * kiểu chung nào ràng chúng lại.
   */
  function buildHandoffHrefAsFrontend(
    target: string,
    h: { appToken?: string; userDid?: string; state?: string | null },
  ): string {
    const url = new URL(target);
    const parts: string[] = [];
    if (h.appToken) parts.push(`app_token=${encodeURIComponent(h.appToken)}`);
    if (h.userDid) parts.push(`user_did=${encodeURIComponent(h.userDid)}`);
    if (h.state) parts.push(`state=${encodeURIComponent(h.state)}`);
    url.hash = parts.join("&");
    return url.toString();
  }

  it("thứ Frontend ghi ra, SDK đọc lại đúng từng trường", () => {
    const state = createHandoffState();
    const href = buildHandoffHrefAsFrontend(CB, {
      appToken: APP_TOKEN,
      userDid: "did:phoenix:aaaaaaaaaaaaa:" + "a".repeat(64),
      state,
    });

    const out = readHandoff(href, { expectedState: state });

    expect(out?.appToken).toBe(APP_TOKEN);
    expect(out?.userDid).toBe("did:phoenix:aaaaaaaaaaaaa:" + "a".repeat(64));
    expect(out?.state).toBe(state);
  });

  it("thẻ có ký tự cần thoát vẫn về nguyên vẹn", () => {
    const tokenWithSpecials = "a.b+c/d=e&f#g";
    const href = buildHandoffHrefAsFrontend(CB, { appToken: tokenWithSpecials });
    expect(readHandoff(href)?.appToken).toBe(tokenWithSpecials);
  });
});

/**
 * ── BẢNG ĐỘT BIẾN (chạy tay 2026-09-08, mỗi lần gỡ đúng MỘT mệnh đề) ─────────
 *
 * | # | Mệnh đề gỡ trong `src/sso.ts`                          | Bài đỏ                                                        |
 * |---|--------------------------------------------------------|---------------------------------------------------------------|
 * | 1 | Vòng lặp `FORBIDDEN_HANDOFF_KEYS` trong `readHandoff`   | "session_token trong fragment ⇒ ném…" + "cả ba loại thẻ rộng…" |
 * | 2 | Nhánh `opts.expectedState !== undefined` (bỏ đối chiếu) | "state lệch ⇒ ném…" + "chờ state mà fragment không có state…"  |
 * | 3 | `erase()` trong nhánh `catch` của `consumeHandoff`      | "lượt bàn giao BỊ TỪ CHỐI vẫn được dọn…"                       |
 * | 4 | `erase()` trong nhánh thành công                        | "trả về lượt bàn giao VÀ gỡ thẻ khỏi URL" + "dùng replaceState…"|
 * | 5 | Cổng giao thức http/https trong `buildLoginUrl`         | "giao thức ngoài http/https bị từ chối"                        |
 * | 6 | `crypto.getRandomValues` → `Math.random`                | "dùng nguồn ngẫu nhiên mật mã, không phải Math.random"          |
 * | 7 | Đọc thêm `url.searchParams` làm nguồn dự phòng cho thẻ  | "fragment CÓ mặt nhưng không mang thẻ, query mang thẻ ⇒ vẫn null"|
 *
 * Không lượt nào làm đỏ một bài KHÔNG liên quan. Output thô nằm trong báo cáo
 * của đợt việc này.
 *
 * ⚠ Lượt 7 lúc đầu KHÔNG đỏ bài nào — bài kiểm khi đó dựng URL không có
 * fragment, nên `readHandoff` trả `null` ngay ở dòng `if (!frag)` và chưa bao
 * giờ chạm tới chỗ đọc thẻ. Cổng gác đúng chữ nhưng không gác được mệnh đề.
 * Đã thêm bài có fragment thật; lượt 7 mới đỏ. Ghi lại vì đây đúng là kiểu cổng
 * giả mà chính bộ kiểm này sinh ra để chặn.
 */
