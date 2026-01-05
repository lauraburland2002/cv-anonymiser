import assert from "node:assert";

const API_BASE_URL = process.env.API_BASE_URL; // e.g. [https://xxxx.execute-api.../prod]https://xxxx.execute-api.../prod
const URL = `${API_BASE_URL}/anonymise`;        // change to your real route

async function postJson(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  let json;
  try { json = JSON.parse(text); } catch { json = null; }
  return { res, json, text };
}

(async () => {
  assert(API_BASE_URL, "API_BASE_URL env var not set");

  const payload = {
    text: "Contact me at jane.doe@example.com or +44 7700 900123",
  };

  const { res, json, text } = await postJson(URL, payload);

  // 1) Contract check
  assert.strictEqual(res.status, 200, `Expected 200, got ${res.status}. Body: ${text}`);
  console.log("FULL RESPONSE JSON:", JSON.stringify(json, null, 2));
  assert(json, "Expected JSON response");

  // Adjust these keys to match your actual API response
  const output = json.anonymised_text ?? json.redacted_text ?? json.output ?? "";
  assert(typeof output === "string" && output.length > 0, "Expected a non-empty anonymised output string");

  // 2) Behaviour/privacy check
  assert(!output.includes("jane.doe@example.com"), "Email was not redacted");
  assert(!output.includes("+44 7700 900123"), "Phone number was not redacted");

  console.log("✅ API regression passed");
})();