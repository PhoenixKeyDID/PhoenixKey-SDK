/**
 * PhoenixKey SDK — DID Resolver + JWKS Module
 *
 * Backend: `ResolverController` (`/identifiers`) và `JwksController`
 * (`/.well-known`).
 *
 * - `resolve()`       — GET /identifiers/{did}
 * - `resolveByHash()` — GET /identifiers/hash/{hashHex}
 * - `getJwks()`       — GET /.well-known/jwks.json
 *
 * ## Vì sao module này khác mọi module còn lại
 *
 * Hai đường `/identifiers/*` **không** bọc thân trong `{code, message, result}`
 * như phần còn lại của API. Chúng trả **phong bì DID Resolution ba phần** theo
 * W3C DID Resolution v0.3 — `didDocument` + `didResolutionMetadata` +
 * `didDocumentMetadata` — và trả đúng phong bì đó **kể cả khi lỗi**. Đó là
 * điểm của chuẩn: "không tìm thấy" là một câu trả lời có cấu trúc, không phải
 * một sự cố.
 *
 * Nên {@link ResolverModule.resolve} **không ném** khi máy chủ nói không tìm
 * thấy / DID sai khuôn / phương thức không hỗ trợ. Nó trả về phong bì với
 * `didDocument: null` và `didResolutionMetadata.error` đã điền. Bên gọi đọc
 * `error` thay vì đoán theo mã HTTP.
 *
 * Nó **vẫn ném** `PhoenixKeyError` khi lượt gọi hỏng thật sự: mạng đứt, hết
 * giờ, 5xx không kèm phong bì, hoặc `Accept` không được chấp nhận (406,
 * `not_acceptable` — thân lúc đó là bọc `{code,message,result}` chuẩn, không
 * phải phong bì; SDK luôn gửi `Accept` hợp lệ nên nhánh này chỉ xảy ra khi có
 * proxy sửa header trên đường đi).
 *
 * ## "Đã khai tử" nhận ra bằng cách nào
 *
 * Máy chủ dùng **cùng một** mã `error: "notFound"` cho cả DID chưa từng có
 * (404) lẫn DID đã khai tử (410). Phân biệt duy nhất nằm ở
 * `didDocumentMetadata.deactivated === true` — dùng {@link isDeactivated} cho
 * khỏi phải nhớ.
 *
 * ## Điểm dễ sập bẫy: `versionTime` làm biến mất `service[]`
 *
 * Lượt tra tại-một-thời-điểm trả tài liệu **không có `service[]`**: đủ khoá để
 * xác minh một chữ ký cũ, nhưng không kèm địa chỉ ví. Đó là chủ ý — để người
 * đã thu hồi khoá rút được ví khỏi tra cứu công khai. Cần địa chỉ ví thì gọi
 * KHÔNG kèm `versionTime`.
 *
 * ## Đường chuẩn W3C nằm sau proxy, không phải ở đây
 *
 * Mọi tuyến máy chủ sống dưới `/api/v1`, nên đường thật là
 * `/api/v1/identifiers/{did}`. Quy ước DIF `/1.0/identifiers/{did}` và
 * `/.well-known/jwks.json` ở gốc tên miền chỉ tồn tại nếu người vận hành cấu
 * hình proxy viết lại. SDK gọi thẳng đường thật, không phụ thuộc proxy đó.
 */

import { createFetcher, FetchOptions } from "./fetcher";
import { PhoenixKeyError, W3CDIDDocument } from "./types";

/**
 * Tài liệu DID trả về từ resolver. Là {@link W3CDIDDocument} cộng thêm
 * `service[]` — trường tuỳ chọn theo DID Core 1.0 §5.4, mang địa chỉ ví, và
 * **vắng mặt** ở mọi lượt tra tại-một-thời-điểm.
 */
export type ResolvedDidDocument = W3CDIDDocument & {
  service?: Array<{
    id: string;
    type: string;
    serviceEndpoint: string;
  }>;
};

/** Mã lỗi resolve theo W3C DID Resolution v0.3. */
export type DidResolutionError =
  | "invalidDid"
  | "notFound"
  | "representationNotSupported"
  | "methodNotSupported"
  | "internalError";

/**
 * Phần siêu dữ liệu về **lượt tra**. Trả `contentType` khi thành công, hoặc
 * `error` + `errorMessage` khi không. Hai nhánh loại trừ nhau.
 */
export type DidResolutionMetadata = {
  contentType?: string;
  error?: DidResolutionError | string;
  errorMessage?: string;
};

/** Phần siêu dữ liệu về **tài liệu**. Trường vắng mặt được lược khỏi JSON. */
export type DidDocumentMetadata = {
  created?: string;
  updated?: string;
  /** `true` = DID đã khai tử. Đây là chỗ duy nhất phân biệt 410 với 404. */
  deactivated?: boolean;
  versionId?: string;
  nextUpdate?: string;
  cardanoTxHash?: string;
  cardanoSlot?: number;
  cardanoNetwork?: string;
  /** Vọng lại `versionTime` đã hỏi, khi có. */
  versionTime?: string;
};

/**
 * Phong bì ba phần. `didDocument` null nghĩa là không resolve được — đọc
 * `didResolutionMetadata.error` để biết vì sao.
 *
 * Trường naming ở đây là **camelCase**, ngoại lệ so với phần còn lại của API:
 * đó là hợp đồng W3C, không phải quy ước của PhoenixKey.
 */
export type DidResolutionResult = {
  didDocument: ResolvedDidDocument | null;
  didResolutionMetadata: DidResolutionMetadata;
  didDocumentMetadata?: DidDocumentMetadata;
};

/** Một khoá trong JWKS (RFC 7517). Ed25519 → `kty: "OKP"`, `crv: "Ed25519"`. */
export type JwksKey = {
  kty: string;
  crv: string;
  /** Khoá công khai thô, base64url không đệm. */
  x: string;
  use: string;
  alg: string;
  kid: string;
};

export type Jwks = {
  keys: JwksKey[];
};

/** Tuỳ chọn cho hai đường tra cứu. */
export type ResolveOptions = {
  /**
   * Tra tại một thời điểm, ISO-8601 (vd `"2026-01-15T10:30:00Z"`). Vắng =
   * trạng thái hiện tại.
   *
   * ⚠ Lượt có `versionTime` trả tài liệu **không có `service[]`** — xem phần
   * đầu tệp. Sai khuôn ISO-8601 thì máy chủ ném `enum_invalid_value` (9800)
   * chứ không lặng lẽ bỏ qua tham số.
   */
  versionTime?: string;
};

/**
 * DID này đã khai tử chưa.
 *
 * Có hàm riêng vì phép kiểm dễ viết sai: `error === "notFound"` **không** phân
 * biệt được "chưa từng tồn tại" với "đã khai tử" — máy chủ dùng chung một mã
 * cho cả hai, chỉ khác mã HTTP (404 với 410) mà phong bì thì không mang mã
 * HTTP. Dấu hiệu thật nằm ở `didDocumentMetadata.deactivated`.
 */
export function isDeactivated(result: DidResolutionResult): boolean {
  return result.didDocumentMetadata?.deactivated === true;
}

/** Lượt tra thành công (có tài liệu) hay không. */
export function isResolved(result: DidResolutionResult): boolean {
  return result.didDocument !== null && result.didDocument !== undefined;
}

/** Media type resolver phục vụ; gửi kèm để khớp thương lượng nội dung. */
const DID_RESOLUTION_MEDIA_TYPE = "application/did-resolution+json";

export class ResolverModule {
  private readonly fetch: ReturnType<typeof createFetcher>;

  constructor(private readonly baseUrl: string) {
    this.fetch = createFetcher(baseUrl);
  }

  /**
   * Tra một DID về tài liệu W3C. Công khai, không cần thẻ phiên.
   *
   * Trả phong bì cho **mọi** kết quả resolve — kể cả không tìm thấy, sai
   * khuôn, đã khai tử, phương thức không hỗ trợ. Ném khi lượt gọi hỏng thật
   * (mạng, hết giờ, 5xx trần, 406).
   *
   * @example
   * ```ts
   * const res = await client.resolver.resolve(did);
   * if (isResolved(res)) {
   *   useKeys(res.didDocument!.verificationMethod);
   * } else if (isDeactivated(res)) {
   *   show("Danh tính này đã khai tử");
   * } else {
   *   show(res.didResolutionMetadata.errorMessage ?? "Không tra được");
   * }
   * ```
   */
  async resolve(did: string, opts?: ResolveOptions): Promise<DidResolutionResult> {
    return this.resolveEnvelope(
      `/identifiers/${encodeURIComponent(did)}${queryOf(opts)}`,
    );
  }

  /**
   * Tra ngược từ **mốc neo 32 byte** về tài liệu DID.
   *
   * Dành cho bên xác minh ở ngoài đã có `blake2b_256(UTF-8(did))` trên chuỗi
   * nhưng không có chuỗi DID: mốc neo là thứ nằm trong giao dịch, chuỗi DID
   * thì không. `hashHex` là 64 ký tự hex thường; sai độ dài hoặc có ký tự
   * ngoài hex thì máy chủ ném `enum_invalid_value` (9800) — đó là lỗi đầu vào,
   * không phải phong bì "không tìm thấy".
   *
   * Cùng luật `versionTime` như {@link resolve}, kể cả việc mất `service[]`.
   */
  async resolveByHash(
    hashHex: string,
    opts?: ResolveOptions,
  ): Promise<DidResolutionResult> {
    return this.resolveEnvelope(
      `/identifiers/hash/${encodeURIComponent(hashHex)}${queryOf(opts)}`,
    );
  }

  /**
   * Bộ khoá công khai máy chủ dùng để ký `session_token` / `app_token`
   * (RFC 7517). Công khai, không auth, máy chủ gợi ý đệm 1 giờ.
   *
   * ⚠ **Đây chỉ là phép ĐỌC.** Nó không xác minh gì cả. Muốn xác minh một
   * `app_token` thì dùng `AppTokenVerifier`
   * (`@phoenixkeydid/phoenixkey-sdk/verifier`) — nó tự lấy JWKS, tự đệm, và
   * kiểm chữ ký Ed25519 + hạn dùng + `aud`. Tự so khoá bằng tay từ hàm này là
   * đường ngắn nhất tới một phép kiểm thiếu bước.
   *
   * ⚠ Máy chủ hiện công bố **một** khoá và lượt xác minh chưa tra theo `kid`.
   * Trước lần xoay khoá đầu tiên, cả hai phía phải nối tra-cứu-theo-`kid`;
   * chưa nối thì một bộ nhiều khoá sẽ được dùng sai khoá đầu tiên.
   */
  async getJwks(): Promise<Jwks> {
    return this.fetch<Jwks>("/.well-known/jwks.json");
  }

  /**
   * Lượt gọi chung cho hai đường `/identifiers/*`: lấy phong bì ra khỏi cả
   * nhánh thành công lẫn nhánh mã lỗi HTTP.
   *
   * Bộ lấy dữ liệu dùng chung đã đọc sẵn thân JSON của phản hồi lỗi và cất
   * vào `err.details`; ở đây chỉ cần nhận ra nó là phong bì DID Resolution.
   * Không nhận ra được thì lỗi là lỗi thật — ném tiếp, không nuốt.
   */
  private async resolveEnvelope(path: string): Promise<DidResolutionResult> {
    try {
      return await this.fetch<DidResolutionResult>(path, {
        method: "GET",
        headers: { Accept: DID_RESOLUTION_MEDIA_TYPE },
      } as FetchOptions);
    } catch (err) {
      if (err instanceof PhoenixKeyError && isEnvelope(err.details)) {
        return err.details;
      }
      throw err;
    }
  }
}

/** Thân lỗi có đúng là phong bì DID Resolution không. */
function isEnvelope(details: unknown): details is DidResolutionResult {
  if (typeof details !== "object" || details === null) return false;
  const meta = (details as { didResolutionMetadata?: unknown }).didResolutionMetadata;
  return typeof meta === "object" && meta !== null;
}

function queryOf(opts?: ResolveOptions): string {
  if (!opts?.versionTime) return "";
  return `?versionTime=${encodeURIComponent(opts.versionTime)}`;
}
