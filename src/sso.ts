/**
 * PhoenixKey SDK — bàn giao phiên đăng nhập cho trang web bên thứ ba
 *
 * Đây là NỬA CÒN LẠI của luồng "quét bằng điện thoại, trang web có phiên".
 * Nửa kia — trang đăng nhập phoenixkey.me — đã có: nó mở phiên, hiện QR, chờ
 * điện thoại duyệt, rồi đổi `session_token` lấy `app_token` và chuyển hướng về
 * `redirect_uri` của bạn. Từ đó trở đi, TRƯỚC bản này, không có mã nào trong
 * cả hệ đọc lấy thứ vừa được giao. Đo 2026-09-08: `grep -rn "location.hash"`
 * trên cả `PhoenixKey-SDK/src` lẫn `PhoenixKey-Frontend/src` — KHÔNG một kết
 * quả. Mỗi bên tích hợp phải tự viết lại đoạn này, và đoạn này là chỗ dễ làm
 * hỏng nhất trong cả luồng.
 *
 * ## Vòng đầy đủ
 *
 * ```ts
 * // ── 1. Trang của bạn: đẩy người dùng sang PhoenixKey ─────────────────────
 * const state = createHandoffState();
 * sessionStorage.setItem("pk_state", state);      // để đối chiếu ở bước 3
 * location.assign(buildLoginUrl({
 *   redirectUri: "https://app.cua-ban.com/callback",
 *   state,
 * }));
 *
 * // ── 2. Người dùng quét QR bằng app PhoenixKey, duyệt bằng sinh trắc ──────
 * //     (phoenixkey.me tự lo; nó KHÔNG gửi session_token đi đâu cả)
 *
 * // ── 3. Trang /callback của bạn: nhận, và XOÁ khỏi thanh địa chỉ ──────────
 * const handoff = consumeHandoff({
 *   expectedState: sessionStorage.getItem("pk_state") ?? undefined,
 * });
 * if (!handoff) return;                            // không phải lượt bàn giao
 * sessionStorage.removeItem("pk_state");
 *
 * // ── 4. Máy chủ CỦA BẠN kiểm thẻ, rồi mới tin ─────────────────────────────
 * await fetch("/api/dang-nhap", {
 *   method: "POST",
 *   body: JSON.stringify({ app_token: handoff.appToken }),
 * });
 * // phía máy chủ:
 * //   const claims = await new AppTokenVerifier().verify(appToken, MY_SERVICE_DID);
 * ```
 *
 * ## Ba điều mô-đun này giữ, và vì sao
 *
 * **1. Thẻ chỉ được đọc từ FRAGMENT, không bao giờ từ chuỗi truy vấn.** Fragment
 * (`#…`) không rời trình duyệt: nó không vào `Referer` gửi sang trang khác,
 * không vào log của proxy, không vào log truy cập của máy chủ. Tham số truy vấn
 * (`?…`) đi hết vào những chỗ đó. Nếu `readHandoff` cũng nhận thẻ ở query cho
 * "tiện", thì một trang đăng nhập viết sai — hoặc một kẻ dựng liên kết —
 * biến chỗ rò thành đường hợp lệ. Nên nó KHÔNG nhận.
 *
 * **2. Fragment chứa `session_token` ⇒ NÉM, không dùng.** `session_token` là
 * phiên toàn quyền thọ 24 giờ. Nó không có việc gì ở đây; thứ được giao phải là
 * `app_token` ràng vào đúng một `aud` và sống 15 phút. Bản cũ của trang đăng
 * nhập từng đính đúng `session_token` vào fragment này. Nếu bên tích hợp gặp
 * một máy chủ như thế mà cứ im lặng dùng, thì lỗ hổng ấy sống tiếp ở phía họ,
 * và không ai đo được. Ném là để nó kêu lên.
 *
 * **3. `consumeHandoff` XOÁ fragment khỏi URL ngay khi đọc xong.** Đọc mà không
 * xoá thì `app_token` nằm lại trên thanh địa chỉ, vào lịch sử trình duyệt, đi
 * theo mọi lần người dùng chép URL hay bấm chia sẻ, và còn nguyên đó khi họ
 * đưa máy cho người khác. `app_token` là thẻ mang-là-dùng: ai cầm chuỗi thì
 * dùng được nó tới `exp`. Bài học vốn đã đắt một lần với `session_token` — lặp
 * lại nó ở bước sau, với thẻ ngắn hạn hơn, vẫn là lặp lại.
 */

import { PhoenixKeyError } from "./types";

// ─── Hợp đồng tên khoá trong fragment ─────────────────────────────────────────
//
// Đây là hợp đồng GIỮA HAI KHO: `PhoenixKey-Frontend/src/lib/redirect.ts`
// (`buildHandoffHref`) ghi các khoá này, mô-đun này đọc chúng. Đổi tên ở một
// bên mà quên bên kia thì mọi bên tích hợp đứt im lặng — không lỗi, không log,
// chỉ là `readHandoff` trả `null` mãi mãi. Đặt tên hằng số để chỗ nào cũng trỏ
// về một nguồn, và để bài kiểm ghim được đúng CHUỖI.

/** Khoá mang thẻ app trong fragment. */
export const HANDOFF_KEY_APP_TOKEN = "app_token";
/** Khoá mang DID người dùng trong fragment. */
export const HANDOFF_KEY_USER_DID = "user_did";
/** Khoá mang `state` do chính trang của bạn sinh ra ở bước 1. */
export const HANDOFF_KEY_STATE = "state";

/**
 * Những thứ TUYỆT ĐỐI không được có mặt trong một lượt bàn giao.
 *
 * Cả ba đều là thẻ rộng hơn `app_token` rất nhiều: `session_token` mở mọi
 * endpoint của người dùng trong 24 giờ, `linked_device_token` cho phép mở phiên
 * mới suốt 30 ngày mà không cần quét lại, `temp_token` mở luồng duyệt của một
 * phiên đăng nhập đang chờ. Thấy bất kỳ cái nào ⇒ máy chủ đầu kia đang làm sai;
 * nhận bừa là mang cái sai đó về nhà mình.
 */
export const FORBIDDEN_HANDOFF_KEYS: readonly string[] = [
  "session_token",
  "linked_device_token",
  "temp_token",
];

/** Trang đăng nhập mặc định của PhoenixKey. */
export const DEFAULT_LOGIN_URL = "https://phoenixkey.me/login";

/**
 * Trần độ dài `nonce` của `POST /auth/token/exchange` phía máy chủ
 * (`TokenExchangeRequest.java`). `state` dài hơn ngần này thì trang đăng nhập
 * KHÔNG ràng nó vào thẻ nữa — nó vẫn quay về nguyên vẹn trong fragment, nhưng
 * bạn mất phần đối chiếu qua claim `nonce`. Xem {@link createHandoffState}.
 */
export const NONCE_MAX_LENGTH = 64;

// ─── Bước 1: rời trang của bạn ────────────────────────────────────────────────

/**
 * Sinh một `state` ngẫu nhiên bằng nguồn ngẫu nhiên MẬT MÃ.
 *
 * `state` là cái chặn được ca: kẻ tấn công gửi cho người dùng một liên kết
 * callback dựng sẵn mang thẻ CỦA KẺ TẤN CÔNG, để người dùng vô tình đăng nhập
 * vào tài khoản của kẻ đó rồi thao tác trong đó. Bạn so `state` quay về với
 * `state` mình đã cất; không khớp thì bỏ.
 *
 * Dùng `crypto.getRandomValues`, KHÔNG `Math.random`: `Math.random` đoán được
 * sau khi quan sát vài giá trị, và một `state` đoán được thì bằng không có.
 * Không có `crypto` thì hàm này NÉM chứ không lặng lẽ hạ cấp — hạ cấp âm thầm
 * đúng là kiểu hỏng mà không ai thấy.
 *
 * Độ dài mặc định 43 ký tự base64url (32 byte) — vừa dưới trần
 * {@link NONCE_MAX_LENGTH}, nên trang đăng nhập ràng được nó vào claim `nonce`
 * của thẻ, cho bạn thêm một đường đối chiếu ở phía máy chủ.
 */
export function createHandoffState(byteLength = 32): string {
  const c = (globalThis as { crypto?: Crypto }).crypto;
  if (!c || typeof c.getRandomValues !== "function") {
    throw new PhoenixKeyError({
      status: 0,
      code: "no_secure_random",
      message:
        "createHandoffState cần crypto.getRandomValues. Không có nguồn ngẫu nhiên " +
        "mật mã thì `state` đoán được, và một `state` đoán được không chặn được gì.",
    });
  }
  const bytes = new Uint8Array(byteLength);
  c.getRandomValues(bytes);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return bytesToBase64Url(bin);
}

export type BuildLoginUrlParams = {
  /** URL trang của bạn nhận bàn giao. Phải là `https:` (hoặc `http:` khi chạy máy cục bộ). */
  redirectUri: string;
  /** Chuỗi từ {@link createHandoffState}. Bỏ trống thì bạn mất lớp chống ghép phiên. */
  state?: string;
  /** Ghi đè trang đăng nhập. Mặc định {@link DEFAULT_LOGIN_URL}. */
  loginUrl?: string;
};

/**
 * Dựng URL đưa người dùng sang trang đăng nhập PhoenixKey.
 *
 * `redirect_uri` và `state` đi ở CHUỖI TRUY VẤN — đúng chỗ của chúng. Chúng
 * không phải bí mật: `redirect_uri` là địa chỉ công khai của chính bạn, `state`
 * chỉ có nghĩa khi ghép với thứ bạn đã cất trong trình duyệt người dùng. Thứ
 * KHÔNG bao giờ được ở query là thẻ, và ở chiều này chưa có thẻ nào tồn tại.
 *
 * `redirectUri` phải khớp NGUYÊN VĂN một phần tử trong `serviceEndpoint[]` của
 * DID Document thuộc ServiceDID của bạn — máy chủ so chuỗi, không chuẩn hoá,
 * nên thừa hay thiếu một dấu `/` cuối là trượt với `redirect_uri_mismatch`.
 * Vì thế hàm này KHÔNG đụng gì vào chuỗi bạn đưa ngoài việc kiểm giao thức.
 */
export function buildLoginUrl(params: BuildLoginUrlParams): string {
  const { redirectUri, state, loginUrl = DEFAULT_LOGIN_URL } = params;

  let target: URL;
  try {
    target = new URL(redirectUri);
  } catch {
    throw new PhoenixKeyError({
      status: 0,
      code: "invalid_redirect_uri",
      message: `redirectUri không parse được thành URL tuyệt đối: ${redirectUri}`,
    });
  }
  // Chặn `javascript:`, `data:`, và mọi lược đồ tuỳ ý. Đây là URL mà trang đăng
  // nhập sẽ chuyển hướng tới sau khi đã có thẻ trong tay.
  if (target.protocol !== "https:" && target.protocol !== "http:") {
    throw new PhoenixKeyError({
      status: 0,
      code: "invalid_redirect_uri",
      message: `redirectUri phải là http(s), nhận được: ${target.protocol}`,
    });
  }

  const url = new URL(loginUrl);
  url.searchParams.set("redirect_uri", redirectUri);
  if (state) url.searchParams.set("state", state);
  return url.toString();
}

// ─── Bước 3: nhận ở trang callback ────────────────────────────────────────────

/** Thứ trang đăng nhập bàn giao lại. */
export type Handoff = {
  /**
   * Thẻ app ngắn hạn, ràng vào đúng một `aud`. **Chưa được kiểm.** Đưa sang máy
   * chủ của bạn và verify bằng `AppTokenVerifier`
   * (`@phoenixkeydid/phoenixkey-sdk/verifier`) trước khi tin bất cứ điều gì
   * trong đó. Đọc claim mà chưa kiểm chữ ký là leo thang quyền, không phải lỗi
   * phân tích chuỗi.
   */
  appToken: string;
  /**
   * DID người dùng, theo lời trang đăng nhập. **Chỉ để hiển thị tạm.** Nguồn
   * đáng tin là claim `sub` của thẻ SAU khi verify — trường này chưa có chữ ký
   * nào bảo vệ.
   */
  userDid?: string;
  /** `state` quay về. Đã được đối chiếu nếu bạn truyền `expectedState`. */
  state?: string;
};

export type ReadHandoffOptions = {
  /**
   * `state` bạn đã cất ở bước 1. Truyền vào thì hàm tự đối chiếu và NÉM khi
   * lệch. Bỏ qua thì bạn phải tự so — và nếu không so ở đâu cả thì luồng của
   * bạn không chặn được ca ghép phiên.
   */
  expectedState?: string;
};

/**
 * Đọc một lượt bàn giao từ URL. Hàm THUẦN — không đụng `location`, không đụng
 * `history` — để kiểm được bằng chuỗi vào/chuỗi ra.
 *
 * @param currentUrl URL đầy đủ của trang callback (kèm fragment)
 * @returns `null` khi fragment không mang lượt bàn giao nào (người dùng vào
 *          thẳng trang, tải lại sau khi đã xoá fragment, …). `null` là "không
 *          có gì để làm", KHÔNG phải lỗi.
 * @throws  `PhoenixKeyError` khi có thứ gì đó SAI: thẻ rộng hơn mức được phép
 *          nằm trong fragment, hoặc `state` không khớp. Cả hai ca đều không
 *          được nuốt — nuốt là để cái sai chạy tiếp.
 */
export function readHandoff(
  currentUrl: string,
  opts: ReadHandoffOptions = {},
): Handoff | null {
  const url = new URL(currentUrl);

  // CHỈ fragment. Không có nhánh nào đọc `url.searchParams` ở đây, và đừng thêm:
  // query đi vào `Referer`, vào log proxy, vào log máy chủ.
  const frag = url.hash.startsWith("#") ? url.hash.slice(1) : url.hash;
  if (!frag) return null;

  const params = new URLSearchParams(frag);

  // Cổng chặn TRƯỚC khi đọc bất cứ thứ gì dùng được. Đặt sau thì có nhánh trả
  // về thẻ trong khi fragment vẫn chứa `session_token`.
  for (const forbidden of FORBIDDEN_HANDOFF_KEYS) {
    if (params.has(forbidden)) {
      throw new PhoenixKeyError({
        status: 0,
        code: "forbidden_token_in_handoff",
        message:
          `Fragment bàn giao mang '${forbidden}'. Chỉ '${HANDOFF_KEY_APP_TOKEN}' ` +
          `được phép rời trang đăng nhập; '${forbidden}' là thẻ rộng hơn nhiều và ` +
          `đang nằm trong URL, tức là đã vào lịch sử trình duyệt. Máy chủ đầu kia ` +
          `đang chạy bản cũ hoặc bị dựng sai — đừng dùng lượt bàn giao này.`,
      });
    }
  }

  const appToken = params.get(HANDOFF_KEY_APP_TOKEN);
  if (!appToken) return null;

  const state = params.get(HANDOFF_KEY_STATE) ?? undefined;
  if (opts.expectedState !== undefined && state !== opts.expectedState) {
    throw new PhoenixKeyError({
      status: 0,
      code: "state_mismatch",
      message:
        "`state` quay về không khớp cái đã cất. Lượt bàn giao này không phải do " +
        "trang của bạn khởi động — có thể là thẻ của người khác được đưa vào máy " +
        "người dùng. Bỏ nó đi.",
    });
  }

  return {
    appToken,
    userDid: params.get(HANDOFF_KEY_USER_DID) ?? undefined,
    state,
  };
}

/**
 * Xoá phần fragment khỏi một URL, giữ nguyên đường dẫn và chuỗi truy vấn.
 *
 * Hàm thuần, tách riêng để kiểm được rằng thứ còn lại KHÔNG chứa thẻ mà vẫn
 * giữ đúng những gì trang của bạn cần (ví dụ `?next=/bang-dieu-khien`).
 */
export function stripHandoffFragment(currentUrl: string): string {
  const url = new URL(currentUrl);
  url.hash = "";
  // `URL` để lại dấu `#` trơ khi gán chuỗi rỗng ở một số bản; cắt cho sạch để
  // thanh địa chỉ không còn dấu vết nào của lượt bàn giao.
  return url.toString().replace(/#$/, "");
}

/**
 * Như {@link readHandoff}, nhưng chạy trong trình duyệt và **XOÁ fragment khỏi
 * thanh địa chỉ** ngay sau khi đọc.
 *
 * Xoá bằng `history.replaceState` chứ không `location.hash = ""`: `replaceState`
 * THAY mục hiện tại trong lịch sử, còn gán `location.hash` THÊM một mục mới —
 * mục cũ, mục còn mang thẻ, vẫn nằm đó cho nút Quay lại. Đó đúng là thứ ta đang
 * cố gỡ bỏ.
 *
 * Fragment được xoá kể cả khi lượt bàn giao bị TỪ CHỐI (thẻ cấm, `state` lệch):
 * lỗi vẫn ném ra cho bạn xử, nhưng thẻ không được phép nằm lại trên thanh địa
 * chỉ chỉ vì ta đã ném sớm.
 *
 * @returns `null` khi không có lượt bàn giao nào trong URL.
 * @throws  như {@link readHandoff}.
 */
export function consumeHandoff(opts: ReadHandoffOptions = {}): Handoff | null {
  const w = globalThis as {
    location?: { href: string };
    history?: { replaceState(d: unknown, t: string, u: string): void };
  };
  if (!w.location?.href) return null; // SSR — không có URL nào để đọc

  const href = w.location.href;
  const erase = () => {
    const cleaned = stripHandoffFragment(href);
    if (cleaned !== href) w.history?.replaceState(null, "", cleaned);
  };

  try {
    const handoff = readHandoff(href, opts);
    // Chỉ xoá khi thật sự CÓ fragment mang thứ gì đó — tránh viết vào lịch sử
    // một cách vô cớ ở mọi lần tải trang thường.
    if (handoff !== null) erase();
    return handoff;
  } catch (err) {
    // Từ chối rồi thì vẫn phải dọn. Thẻ nằm lại trên thanh địa chỉ sau một lượt
    // bàn giao bị từ chối vẫn là thẻ nằm trong lịch sử trình duyệt.
    erase();
    throw err;
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** base64url từ một chuỗi nhị phân (mỗi ký tự = 1 byte). */
function bytesToBase64Url(bin: string): string {
  let b64: string;
  if (typeof btoa === "function") {
    b64 = btoa(bin);
  } else {
    const NodeBuffer = (
      globalThis as { Buffer?: { from(s: string, enc: string): { toString(enc: string): string } } }
    ).Buffer;
    if (!NodeBuffer) throw new Error("bytesToBase64Url: no btoa or Buffer available");
    b64 = NodeBuffer.from(bin, "binary").toString("base64");
  }
  return b64.replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}
