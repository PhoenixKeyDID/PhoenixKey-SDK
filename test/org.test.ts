/**
 * `OrgModule` — vòng đời OrgDID + Grant uỷ quyền LAMP.
 *
 * Bốn điều được chốt ở đây:
 *  1. tám đường đi đúng tuyến `OrgController`, kể cả `/grants/{id}/consume`
 *     nằm ở gốc `/identity/org` chứ KHÔNG lồng dưới `{orgDid}`;
 *  2. `list()` không nhận tham số DID nào — chống dựng máy lập bản đồ
 *     người → tổ chức;
 *  3. `amount_lamp` giữ nguyên CHUỖI, không bị đưa qua kiểu số;
 *  4. trường tuỳ chọn vắng hẳn khỏi thân khi không truyền.
 */

import { OrgModule } from "../src/org";

const BASE = "https://api.example.test/api/v1";
const TOKEN = "session-token";
const ORG_DID = "did:phoenix:aaaaaaahl4nn6:" + "ab".repeat(32);
const OWNER_DID = "did:phoenix:aaaaaaahomxng:" + "cd".repeat(32);
const GRANT_ID = "6f1c8f3e-0000-4000-8000-000000000001";

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
  return new OrgModule(BASE, () => token);
}

const GRANT_PARAMS = {
  action: "mint:LAMP" as const,
  resource: "pot-1",
  amountLamp: "26000000000000000",
  ownerDid: OWNER_DID,
  ownerSignature: "3044beef",
  nonce: "n-lampgrant-001",
};

afterEach(() => {
  jest.restoreAllMocks();
});

describe("OrgModule — tám tuyến đường", () => {
  it("list · create · founding · upgrade-authority", async () => {
    mockOk({ orgs: [] });
    const m = mod();
    await m.list();
    await m.create({
      ownerDid: OWNER_DID,
      name: "Alpha TNHH",
      ownerSignature: "3044",
      nonce: "n-1",
    });
    await m.found({
      founders: [{ ownerDid: OWNER_DID, ownerSignature: "3044" }],
      threshold: 2,
      name: "Hợp Tác Xã",
      nonce: "n-2",
    });
    await m.upgradeAuthority(ORG_DID, {
      currentOwnerDid: OWNER_DID,
      ownerSignature: "3044",
      newMembers: [{ ownerDid: OWNER_DID, ownerSignature: "3045" }],
      newThreshold: 2,
      nonce: "n-3",
    });

    expect(calls).toEqual([
      `${BASE}/identity/org`,
      `${BASE}/identity/org/create`,
      `${BASE}/identity/org/founding`,
      `${BASE}/identity/org/${encodeURIComponent(ORG_DID)}/upgrade-authority`,
    ]);
  });

  it("bốn đường Grant — consume nằm ở GỐC /identity/org, không lồng dưới {orgDid}", async () => {
    mockOk({});
    const m = mod();
    await m.issueLampGrant(ORG_DID, GRANT_PARAMS);
    await m.listLampGrants(ORG_DID);
    await m.consumeLampGrant(GRANT_ID, {
      txHash: "ab".repeat(32),
      nonce: "n-c",
      consumerSignature: "3044",
    });
    await m.revokeLampGrant(ORG_DID, GRANT_ID, {
      ownerDid: OWNER_DID,
      ownerSignature: "3044",
      nonce: "n-r",
    });

    const org = encodeURIComponent(ORG_DID);
    expect(calls).toEqual([
      `${BASE}/identity/org/${org}/mint-lamp`,
      `${BASE}/identity/org/${org}/grants`,
      // Đây là chỗ dễ đoán sai nhất: người tiêu Grant không biết OrgDID nào
      // phát ra nó, nên máy chủ cố ý đặt đường này ngoài phạm vi {orgDid}.
      `${BASE}/identity/org/grants/${GRANT_ID}/consume`,
      `${BASE}/identity/org/${org}/grants/${GRANT_ID}/revoke`,
    ]);
  });
});

describe("OrgModule — list không nhận DID từ bên ngoài", () => {
  it("URL trần, không phần truy vấn, không owner_did", async () => {
    mockOk({ orgs: [] });
    await mod().list();
    expect(calls[0]).toBe(`${BASE}/identity/org`);
    expect(calls[0]).not.toContain("?");
    expect(calls[0]).not.toContain("owner_did");
  });

  it("gắn Bearer; chưa đăng nhập thì ném trước khi đi mạng", async () => {
    const f = mockOk({ orgs: [] });
    await mod().list();
    const init = f.mock.calls[0][1] as RequestInit;
    expect((init.headers as Record<string, string>).Authorization).toBe(
      `Bearer ${TOKEN}`,
    );

    jest.restoreAllMocks();
    mockOk({ orgs: [] });
    await expect(mod(null).list()).rejects.toThrow("No session token");
    expect(calls).toHaveLength(0);
  });

  it("listLampGrants cũng đòi thẻ phiên", async () => {
    mockOk({ grants: [] });
    await expect(mod(null).listLampGrants(ORG_DID)).rejects.toThrow("No session token");
    expect(calls).toHaveLength(0);
  });
});

describe("OrgModule — amount_lamp là CHUỖI, không phải số", () => {
  it("số lớn hơn Number.MAX_SAFE_INTEGER đi qua nguyên vẹn từng chữ số", async () => {
    const f = mockOk({});
    await mod().issueLampGrant(ORG_DID, GRANT_PARAMS);
    const init = f.mock.calls[0][1] as RequestInit;
    const raw = String(init.body);

    // Chốt trên chuỗi thô: nếu ai đó bọc `Number()` vào đường này, con số
    // 26000000000000000 sẽ ra khác và JSON sẽ không còn dấu nháy quanh nó.
    expect(raw).toContain('"amount_lamp":"26000000000000000"');
    const body = JSON.parse(raw);
    expect(typeof body.amount_lamp).toBe("string");
    expect(body.amount_lamp).toBe("26000000000000000");
    // Bằng chứng vì sao phải là chuỗi: ở độ lớn này, đi qua kiểu số của
    // JavaScript là mất chữ số cuối mà KHÔNG có gì báo.
    expect(Number.isSafeInteger(Number(body.amount_lamp))).toBe(false);
    expect(String(Number("26000000000000001"))).toBe("26000000000000000");
    expect(String(Number("26000000000000001"))).not.toBe("26000000000000001");
  });

  it("phản hồi giữ amount_lamp dạng chuỗi", async () => {
    mockOk({ grant_id: GRANT_ID, amount_lamp: "26000000000000000", status: "ISSUED" });
    const res = await mod().issueLampGrant(ORG_DID, GRANT_PARAMS);
    expect(typeof res.amount_lamp).toBe("string");
  });
});

describe("OrgModule — trường tuỳ chọn vắng hẳn khi không truyền", () => {
  it("grantee_did / valid_ttl_seconds không xuất hiện nếu bên gọi bỏ trống", async () => {
    const f = mockOk({});
    await mod().issueLampGrant(ORG_DID, GRANT_PARAMS);
    const keys = Object.keys(JSON.parse(String((f.mock.calls[0][1] as RequestInit).body ?? "{}")));
    expect(keys).not.toContain("grantee_did");
    expect(keys).not.toContain("valid_ttl_seconds");
  });

  it("có truyền thì gửi đúng tên snake_case", async () => {
    const f = mockOk({});
    await mod().issueLampGrant(ORG_DID, {
      ...GRANT_PARAMS,
      granteeDid: OWNER_DID,
      validTtlSeconds: 3600,
    });
    const body = JSON.parse(String((f.mock.calls[0][1] as RequestInit).body));
    expect(body.grantee_did).toBe(OWNER_DID);
    expect(body.valid_ttl_seconds).toBe(3600);
    expect(Object.keys(body)).not.toContain("validTtlSeconds");
  });

  it("registration_number vắng khỏi create khi không truyền", async () => {
    const f = mockOk({});
    await mod().create({
      ownerDid: OWNER_DID,
      name: "Alpha TNHH",
      ownerSignature: "3044",
      nonce: "n-1",
    });
    const body = JSON.parse(String((f.mock.calls[0][1] as RequestInit).body));
    expect(Object.keys(body)).not.toContain("registration_number");
    expect(body).toEqual({
      owner_did: OWNER_DID,
      name: "Alpha TNHH",
      owner_signature: "3044",
      nonce: "n-1",
    });
  });

  it("founders / new_members được san phẳng sang snake_case từng phần tử", async () => {
    const f = mockOk({});
    await mod().found({
      founders: [
        { ownerDid: OWNER_DID, ownerSignature: "3044" },
        { ownerDid: ORG_DID, ownerSignature: "3045" },
      ],
      threshold: 2,
      name: "Hợp Tác Xã",
      registrationNumber: "0101234567",
      nonce: "n-2",
    });
    const body = JSON.parse(String((f.mock.calls[0][1] as RequestInit).body));
    expect(body.founders).toEqual([
      { owner_did: OWNER_DID, owner_signature: "3044" },
      { owner_did: ORG_DID, owner_signature: "3045" },
    ]);
    // Mã số đăng ký NẰM TRONG chữ ký — nó phải thật sự lên dây, không được rơi.
    expect(body.registration_number).toBe("0101234567");
  });
});

describe("OrgModule — mã lỗi vòng đời Grant phân biệt được", () => {
  it("1348 → 'org_grant_unsupported' (org m-of-n chưa phát Grant được)", async () => {
    mockErr(1348, 409, "Org LAMP grant not supported for this authority model");
    await expect(mod().issueLampGrant(ORG_DID, GRANT_PARAMS)).rejects.toMatchObject({
      code: "org_grant_unsupported",
      status: 409,
    });
  });

  it("1373 CONSUMED khác 1374 REVOKED khác 1375 EXPIRED", async () => {
    const cases: Array<[number, string]> = [
      [1373, "grant_already_consumed"],
      [1374, "grant_already_revoked"],
      [1375, "grant_expired"],
    ];
    for (const [raw, expected] of cases) {
      mockErr(raw, 409);
      await expect(
        mod().revokeLampGrant(ORG_DID, GRANT_ID, {
          ownerDid: OWNER_DID,
          ownerSignature: "3044",
          nonce: "n-r",
        }),
      ).rejects.toMatchObject({ code: expected });
      jest.restoreAllMocks();
    }
  });

  it("1377 → 'grant_consumer_key_not_configured' (503, hỏng về phía an toàn)", async () => {
    mockErr(1377, 503, "treasury public key not configured");
    await expect(
      mod().consumeLampGrant(GRANT_ID, {
        txHash: "ab".repeat(32),
        nonce: "n-c",
        consumerSignature: "3044",
      }),
    ).rejects.toMatchObject({
      code: "grant_consumer_key_not_configured",
      status: 503,
    });
  });

  it("1341 → 'owner_signature_invalid'; 1345 → 'org_authority_not_upgradable'", async () => {
    mockErr(1341, 403);
    await expect(
      mod().create({
        ownerDid: OWNER_DID,
        name: "Alpha",
        ownerSignature: "bad",
        nonce: "n-1",
      }),
    ).rejects.toMatchObject({ code: "owner_signature_invalid" });

    jest.restoreAllMocks();
    mockErr(1345, 409);
    await expect(
      mod().upgradeAuthority(ORG_DID, {
        currentOwnerDid: OWNER_DID,
        ownerSignature: "3044",
        newMembers: [{ ownerDid: OWNER_DID, ownerSignature: "3045" }],
        newThreshold: 2,
        nonce: "n-3",
      }),
    ).rejects.toMatchObject({ code: "org_authority_not_upgradable" });
  });
});
