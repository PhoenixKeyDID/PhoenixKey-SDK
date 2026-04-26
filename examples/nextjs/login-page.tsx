"use client";

/**
 * Example: Login page using PhoenixKey SDK
 * Framework: Next.js 14+ (App Router)
 *
 * Flow:
 * 1. initSession()           → get session_id + temp_token
 * 2. Render QR code          → user scans with Aladin app
 *    OR pushLinkedDevice()   → push notification if device already linked
 * 3. openStream()            → SSE waits for Aladin approval
 * 4. On "approved" event     → store session, redirect to dashboard
 */

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import QRCode from "qrcode"; // npm install qrcode
import { PhoenixKeyClient, ResilientSSE, LoginSessionStatus, LoginSessionInit } from "@phoenixkey/sdk";

// ─── Instantiate once at module level ──────────────────────────────────────────
const phoenix = new PhoenixKeyClient({
  apiKey:  process.env.NEXT_PUBLIC_PHOENIXKEY_API_KEY!,
  appId:   "my-app",
  appName: "My App",
});

// ─── Component ────────────────────────────────────────────────────────────────
export default function LoginPage() {
  const router = useRouter();
  const streamRef = useRef<ResilientSSE | null>(null);

  const [sessionData, setSessionData] = useState<LoginSessionInit | null>(null);
  const [qrDataUrl, setQrDataUrl] = useState<string>("");
  const [status, setStatus] = useState<"idle" | "waiting" | "approved" | "rejected" | "expired">("idle");
  const [hasDevice, setHasDevice] = useState(false);

  // Redirect if already logged in
  useEffect(() => {
    if (phoenix.isLoggedIn()) router.replace("/dashboard");
    setHasDevice(phoenix.session.hasLinkedDevice());
  }, []);

  // ── Start login ──────────────────────────────────────────────────────────────
  async function startLogin() {
    setStatus("waiting");

    // Step 1: Bootstrap session
    const data = await phoenix.auth.initSession();
    setSessionData(data);

    // Step 2a: If device is linked, push notification instead of QR
    if (phoenix.session.hasLinkedDevice()) {
      await phoenix.auth.pushLinkedDevice();
      // QR is still shown as fallback in case push doesn't arrive
    }

    // Step 2b: Render QR — encodes deep link that opens Aladin
    const qrPayload = `aladin://auth?session=${data.session_id}&app=my-app`;
    const qr = await QRCode.toDataURL(qrPayload, { width: 240, margin: 2 });
    setQrDataUrl(qr);

    // Step 3: Open SSE stream — primary path for receiving approval
    const stream = phoenix.auth.openStream(data.session_id, data.temp_token, {
      onMessage: ({ data: evt }) => handleStatusUpdate(evt, stream),

      // On reconnect: poll once to catch missed events
      onReconnect: async () => {
        const st = await phoenix.auth.getStatus(data.session_id, data.temp_token);
        handleStatusUpdate(st, stream);
      },
    });

    streamRef.current = stream;
    await stream.connect();
  }

  // ── Handle status update (from SSE or poll) ───────────────────────────────
  function handleStatusUpdate(
    st: LoginSessionStatus,
    stream: ResilientSSE,
  ) {
    setStatus(st.status as typeof status);

    if (st.status === "approved") {
      stream.close();
      // Persist session
      phoenix.session.set(st.session_token, st.user_did);
      // Persist linked device for next login (skip QR)
      if (st.linked_device_token) {
        phoenix.session.setLinkedDevice(st.linked_device_token);
      }
      router.push("/dashboard");
    }

    if (st.status === "rejected" || st.status === "expired") {
      stream.close();
    }
  }

  // ── Cleanup on unmount ───────────────────────────────────────────────────
  useEffect(() => {
    return () => streamRef.current?.close();
  }, []);

  // ── Render ───────────────────────────────────────────────────────────────
  return (
    <main style={{ textAlign: "center", padding: "2rem" }}>
      <h1>Đăng nhập</h1>

      {status === "idle" && (
        <button onClick={startLogin}>
          {hasDevice ? "Đăng nhập qua Aladin" : "Tạo / khôi phục danh tính"}
        </button>
      )}

      {status === "waiting" && qrDataUrl && (
        <div>
          <p>
            {hasDevice
              ? "Kiểm tra thông báo trên Aladin App, hoặc quét mã QR"
              : "Mở Aladin App và quét mã QR để xác nhận"}
          </p>
          <img src={qrDataUrl} alt="QR đăng nhập PhoenixKey" width={240} />
          <p style={{ color: "#888", fontSize: "0.85rem" }}>
            Hết hạn lúc {new Date((sessionData!.expires_at) * 1000).toLocaleTimeString()}
          </p>
        </div>
      )}

      {status === "approved" && <p>✅ Đã xác nhận — đang chuyển hướng...</p>}
      {status === "rejected" && (
        <div>
          <p>❌ Yêu cầu bị từ chối.</p>
          <button onClick={startLogin}>Thử lại</button>
        </div>
      )}
      {status === "expired" && (
        <div>
          <p>⏱ Mã QR đã hết hạn.</p>
          <button onClick={startLogin}>Tạo mã mới</button>
        </div>
      )}
    </main>
  );
}