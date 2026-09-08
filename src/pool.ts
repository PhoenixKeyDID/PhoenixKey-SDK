/**
 * PhoenixKey SDK — Pool + Delegation Module
 *
 * Ba đường ĐỌC, không cần thẻ phiên. Backend: `PoolController`.
 *
 * - `listPools()`          — GET /pools?page=N[&size=M]
 * - `getPool()`            — GET /pools/{poolId}
 * - `getDelegationStatus()`— GET /delegation/status/{stakeAddress}
 *
 * ## Đây là ống dẫn từ Blockfrost, không phải trạng thái do PhoenixKey giữ
 *
 * Máy chủ chuyển tiếp Blockfrost rồi đệm lại. Quyền kiểm soát on-chain
 * (`did_stake`, `did_pool`) nằm ở PhoenixKey-Validator; ba đường này **chỉ để
 * hiển thị**. Không có đường nào ở đây uỷ quyền stake — đừng dựng nút "Uỷ
 * quyền" trên chúng.
 *
 * Hệ quả cần biết: khi tầng Blockfrost phía máy chủ trục trặc hoặc chưa cấu
 * hình khoá, lỗi vọng về là lỗi cổng (5xx / `network_error`), **không** phải
 * `pool_not_found`. Phân biệt hai thứ đó trước khi hiện "không tìm thấy pool"
 * cho người dùng.
 *
 * ## Số dư là CHUỖI, không phải số
 *
 * `live_stake`, `active_stake`, `controlled_amount`… đều là chuỗi thập phân
 * lovelace. Cardano dùng u64; ví lớn trên mainnet vượt `Number.MAX_SAFE_INTEGER`
 * và `Number()` sẽ làm tròn im lặng. Cộng trừ thì dùng `BigInt`.
 *
 * `margin_cost` là phân số 0..1, KHÔNG phải phần trăm — nhân 100 khi hiển thị.
 */

import { createFetcher, FetchOptions } from "./fetcher";

export type PoolListPage = {
  pool_ids: string[];
  page: number;
  count: number;
};

export type PoolDetail = {
  pool_id: string;
  hex: string;
  blocks_minted: number;
  /** Chuỗi thập phân lovelace. */
  live_stake: string;
  /** Phân số bão hoà; > 1 là quá bão hoà. */
  live_saturation: number;
  active_stake: string;
  declared_pledge: string;
  live_pledge: string;
  /** Phân số 0..1, không phải phần trăm. */
  margin_cost: number;
  /** Chuỗi thập phân lovelace, cố định mỗi epoch. */
  fixed_cost: string;
  reward_account: string;
  /** Bốn trường siêu dữ liệu off-chain — null nếu pool không đăng ký. */
  ticker: string | null;
  name: string | null;
  description: string | null;
  homepage: string | null;
};

export type DelegationStatus = {
  stake_address: string;
  /** Khoá stake đã đăng ký chưa. */
  active: boolean;
  /** Pool đang uỷ quyền; null khi chưa uỷ quyền. */
  pool_id: string | null;
  controlled_amount: string;
  rewards_sum: string;
  withdrawable_amount: string;
};

export class PoolModule {
  private readonly fetch: ReturnType<typeof createFetcher>;

  constructor(private readonly baseUrl: string) {
    this.fetch = createFetcher(baseUrl);
  }

  /**
   * Một trang `pool_id`. **Trang đầu là 1**, không phải 0.
   *
   * Blockfrost chốt cứng 100 pool mỗi trang. `size` nhỏ hơn 100 thì máy chủ
   * cắt bớt trước khi trả (đỡ cho máy khách phải gánh cả trang); lớn hơn 100
   * bị ép về 100 — muốn thêm pool thì tăng `page`, không tăng `size`.
   *
   * Luồng thường gặp: hiện danh sách id rồi gọi {@link getPool} khi người dùng
   * chạm vào một dòng, chứ không nạp chi tiết cả trăm pool một lượt.
   *
   * @param page  ≥ 1. Giá trị nhỏ hơn bị máy chủ nâng về 1.
   * @param size  tuỳ chọn, 1..100.
   */
  async listPools(page = 1, size?: number): Promise<PoolListPage> {
    const query = new URLSearchParams({ page: String(page) });
    if (size !== undefined) query.set("size", String(size));
    return this.fetch<PoolListPage>(`/pools?${query.toString()}`);
  }

  /**
   * Chi tiết một pool — hợp nhất số liệu và siêu dữ liệu off-chain trong một
   * lượt gọi. Bốn trường siêu dữ liệu có thể null cùng lúc khi pool không đăng
   * ký off-chain; điều đó **không** có nghĩa pool không tồn tại.
   *
   * Không có pool → `pool_not_found` (1370, 404).
   */
  async getPool(poolId: string): Promise<PoolDetail> {
    return this.fetch<PoolDetail>(`/pools/${encodeURIComponent(poolId)}`);
  }

  /**
   * Trạng thái uỷ quyền của một địa chỉ stake.
   *
   * **Không bao giờ 404.** Tài khoản chưa đăng ký khoá stake vẫn trả về đủ
   * hình dạng: `active: false`, `pool_id: null`, các số dư `"0"`. Đó là câu
   * trả lời thật ("chưa uỷ quyền"), không phải lỗi — đừng bọc nó trong nhánh
   * bắt lỗi.
   *
   * Gọi thiếu `stakeAddress` (đường `/delegation/status` trần) trả
   * `enum_invalid_value` (9800) kèm lời nhắc thiếu đoạn đường dẫn, chứ không
   * phải 404 "không có endpoint" — nhưng SDK luôn ghép đủ nên bên gọi không
   * gặp nhánh đó.
   */
  async getDelegationStatus(stakeAddress: string): Promise<DelegationStatus> {
    return this.fetch<DelegationStatus>(
      `/delegation/status/${encodeURIComponent(stakeAddress)}`,
      { method: "GET" } as FetchOptions,
    );
  }
}
