const cvTextEl = document.getElementById("cvText");
const cvFileEl = document.getElementById("cvFile");
const fileNameEl = document.getElementById("fileName");
const charCountEl = document.getElementById("charCount");

const anonymiseBtn = document.getElementById("anonymiseBtn");
const clearBtn = document.getElementById("clearBtn");

const statusEl = document.getElementById("status");
const outputEl = document.getElementById("output");

const copyBtn = document.getElementById("copyBtn");
const downloadBtn = document.getElementById("downloadBtn");

const apiUrlLabelEl = document.getElementById("apiUrlLabel");

const API_BASE_URL = (window.APP_CONFIG && window.APP_CONFIG.API_BASE_URL) || "";
apiUrlLabelEl.textContent = API_BASE_URL || "Not configured";

function setStatus(message, type = "info") {
statusEl.classList.remove("error");
if (type === "error") statusEl.classList.add("error");
statusEl.textContent = message || "";
}

function setBusy(isBusy) {
anonymiseBtn.disabled = isBusy;
clearBtn.disabled = isBusy;
}

function setOutput(text) {
outputEl.textContent = text || "";
const hasOutput = Boolean(text && text.trim().length);
copyBtn.disabled = !hasOutput;
downloadBtn.disabled = !hasOutput;
}

function updateCharCount() {
charCountEl.textContent = `${cvTextEl.value.length} chars`;
}

cvTextEl.addEventListener("input", updateCharCount);
updateCharCount();

cvFileEl.addEventListener("change", async (e) => {
const file = e.target.files && e.target.files[0];
if (!file) {
fileNameEl.textContent = "No file selected";
return;
}
fileNameEl.textContent = file.name;

// Read only as text (MVP)
const text = await file.text();
cvTextEl.value = text;
updateCharCount();
});

clearBtn.addEventListener("click", () => {
cvTextEl.value = "";
cvFileEl.value = "";
fileNameEl.textContent = "No file selected";
setOutput("");
setStatus("");
updateCharCount();
});

copyBtn.addEventListener("click", async () => {
const text = outputEl.textContent || "";
await navigator.clipboard.writeText(text);
setStatus("Copied output to clipboard.");
setTimeout(() => setStatus(""), 1200);
});

downloadBtn.addEventListener("click", () => {
const text = outputEl.textContent || "";
const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
const url = URL.createObjectURL(blob);

const a = document.createElement("a");
a.href = url;
a.download = "anonymised-cv.txt";
document.body.appendChild(a);
a.click();
a.remove();

URL.revokeObjectURL(url);
});

anonymiseBtn.addEventListener("click", async () => {
try {
setStatus("");
setOutput("");

const inputText = (cvTextEl.value || "").trim();
if (!inputText) {
setStatus("Please paste CV text (or upload a .txt) first.", "error");
return;
}

setBusy(true);
setStatus("Calling anonymise API…");

// We expect: POST { text: "..." } and response: { anonymisedText: "..." }
const res = await fetch(`${API.replace(/\/$/, "")}/anonymise`, {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ text: inputText }),
});

const raw = await res.text();
let data;
try {
data = JSON.parse(raw);
} catch {
throw new Error(`Non-JSON response (${res.status}): ${raw.slice(0, 300)}`);
}

if (!res.ok) {
const msg = data && (data.message || data.error) ? (data.message || data.error) : raw;
throw new Error(`API error ${res.status}: ${msg}`);
}

const anonymisedText =
data.anonymisedText ||
data.body || // some lambdas return { body: "..." }
"";

if (!anonymisedText) {
throw new Error("API responded OK but did not return anonymisedText.");
}

setOutput(anonymisedText);
setStatus("Done.");
} catch (err) {
setStatus(err.message || "Unknown error", "error");
} finally {
setBusy(false);
}
});