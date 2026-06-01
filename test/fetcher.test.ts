import { createFetcher, DEFAULT_TIMEOUT_MS } from "../src/fetcher";
import { PhoenixKeyError } from "../src/types";

const BASE = "https://api.example.test";

afterEach(() => {
  jest.restoreAllMocks();
});

function mockFetch(impl: (url: string, init: RequestInit) => Promise<Response>) {
  return jest.spyOn(globalThis, "fetch").mockImplementation(impl as typeof fetch);
}

describe("createFetcher — envelope + success", () => {
  it("unwraps a DataResponse result on success", async () => {
    mockFetch(async () =>
      new Response(JSON.stringify({ code: 1000, message: "ok", result: { a: 1 } }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    const f = createFetcher(BASE);
    await expect(f("/x")).resolves.toEqual({ a: 1 });
  });
});

describe("createFetcher — timeout", () => {
  it("exposes a 20s default timeout constant", () => {
    expect(DEFAULT_TIMEOUT_MS).toBe(20_000);
  });

  it("maps an AbortSignal.timeout firing to a PhoenixKeyError code 'timeout'", async () => {
    // fetch never resolves on its own; it rejects when the passed signal aborts.
    mockFetch(
      (_, init) =>
        new Promise((_resolve, reject) => {
          const signal = init.signal as AbortSignal;
          if (signal) {
            signal.addEventListener("abort", () => {
              reject(
                signal.reason instanceof Error
                  ? signal.reason
                  : new DOMException("The operation timed out.", "TimeoutError"),
              );
            });
          }
        }),
    );
    const f = createFetcher(BASE);
    const p = f("/slow", { timeoutMs: 10 });
    await expect(p).rejects.toMatchObject({
      code: "timeout",
      status: 0,
    });
    await expect(p).rejects.toBeInstanceOf(PhoenixKeyError);
  });

  it("does NOT time out a fast response", async () => {
    mockFetch(async () =>
      new Response(JSON.stringify({ code: 1000, result: "fast" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    const f = createFetcher(BASE);
    await expect(f("/fast", { timeoutMs: 1000 })).resolves.toBe("fast");
  });

  it("disables timeout with timeoutMs = 0 (no signal armed)", async () => {
    let seenSignal: AbortSignal | null | undefined;
    mockFetch(async (_, init) => {
      seenSignal = init.signal as AbortSignal | null | undefined;
      return new Response(JSON.stringify({ code: 1000, result: "ok" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    });
    const f = createFetcher(BASE);
    await f("/x", { timeoutMs: 0 });
    expect(seenSignal == null).toBe(true);
  });

  it("lets a caller-supplied signal own abort (maps to network_error, not timeout)", async () => {
    mockFetch(
      (_, init) =>
        new Promise((_resolve, reject) => {
          (init.signal as AbortSignal).addEventListener("abort", () => {
            reject(new DOMException("aborted by caller", "AbortError"));
          });
        }),
    );
    const ac = new AbortController();
    const f = createFetcher(BASE);
    const p = f("/x", { signal: ac.signal });
    ac.abort();
    await expect(p).rejects.toMatchObject({ code: "network_error", status: 0 });
  });
});

describe("createFetcher — error mapping", () => {
  it("maps a backend integer code to a string code", async () => {
    mockFetch(async () =>
      new Response(JSON.stringify({ code: 1302, message: "expired" }), {
        status: 401,
        headers: { "Content-Type": "application/json" },
      }),
    );
    const f = createFetcher(BASE);
    await expect(f("/x")).rejects.toMatchObject({ code: "session_expired", status: 401 });
  });
});
