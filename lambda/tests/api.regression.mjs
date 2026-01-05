const API_BASE_URL = process.env.API_BASE_URL;

if (!API_BASE_URL) {
  console.error("Missing API_BASE_URL env var");
  process.exit(1);
}

// small helper
async function check(path, { method = "GET", expectedStatus = 200, expectJson = true } = {}) {
  const url = new URL(path, API_BASE_URL).toString();
  const res = await fetch(url, { method });

  if (res.status !== expectedStatus) {
    const body = await res.text().catch(() => "");
    throw new Error(`${method} ${url} => expected ${expectedStatus}, got ${res.status}. Body: ${body}`);
  }

  if (expectJson) {
    const data = await res.json();
    return { res, data };
  }

  return { res, data: null };
}

(async () => {
  try {
    // 1) health endpoint must be reachable and stable shape
    const { data: health } = await check("/health", { expectedStatus: 200, expectJson: true });

    // adjust these to YOUR real response shape
    // (from your earlier tests it looked like {"ok": true})
    if (health.ok !== true) {
      throw new Error(`GET /health returned unexpected JSON: ${JSON.stringify(health)}`);
    }

    // 2) Optional: ensure API rejects wrong method (regression guard)
    await check("/health", { method: "POST", expectedStatus: 405, expectJson: false });

    console.log("✅ API regression checks passed");
  } catch (err) {
    console.error("❌ API regression checks failed:", err.message);
    process.exit(1);
  }
})();