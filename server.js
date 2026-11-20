// Tiny HTTP server for the bulk-abuse-report tool. Zero dependencies.
//
//   GET  /                      -> public/index.html
//   GET  /batch/<id>            -> public/batch.html
//   GET  /api/batch/<id>        -> JSON state (polled by the batch page)
//   POST /start                 -> multipart form, creates a batch, returns redirect
//   POST /api/retry/<id>/<idx>  -> re-enqueue a failed row
//
// State is in-memory. Per-row submits run through a small worker pool.

import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

import { parseMultipart } from "./multipart.js";
import { submitRow } from "./submitter.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Minimal .env loader (KEY=VALUE per line, # comments). Real env takes priority.
function loadDotenv(file) {
  try {
    const raw = fs.readFileSync(file, "utf8");
    for (const line of raw.split(/\r?\n/)) {
      const m = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/.exec(line);
      if (!m) continue;
      let v = m[2];
      if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
        v = v.slice(1, -1);
      }
      if (!(m[1] in process.env)) process.env[m[1]] = v;
    }
  } catch (e) { if (e.code !== "ENOENT") console.warn(`.env read failed: ${e.message}`); }
}
loadDotenv(path.join(__dirname, ".env"));

const TWOCAPTCHA_API_KEY = process.env.TWOCAPTCHA_API_KEY;
if (!TWOCAPTCHA_API_KEY) {
  console.error(
    "TWOCAPTCHA_API_KEY is not set. Put it in .env (see .env.example) or pass " +
    "it as an environment variable: TWOCAPTCHA_API_KEY=... node server.js"
  );
  process.exit(1);
}
const PORT = Number(process.env.PORT || 5000);
const MAX_WORKERS = 3;

// Mirror every log line to server.log (so operators don't have to redirect stdout).
const LOG_FILE = path.join(__dirname, "server.log");
function log(msg) {
  const line = `${msg}\n`;
  process.stdout.write(line);
  try { fs.appendFileSync(LOG_FILE, line); } catch { /* best-effort */ }
}

// Render a target for a single log line: escape newlines/tabs, cap at 80 chars.
function logTarget(t) {
  const flat = String(t).replace(/\r/g, "\\r").replace(/\n/g, "\\n").replace(/\t/g, "\\t");
  return flat.length > 80 ? `${flat.slice(0, 77)}…` : flat;
}

// Pre-submit validation of the target itself. Blocks obviously bad input so
// we don't burn a captcha on it. Returns null if ok, or a reason string.
function validateTarget(type, value) {
  if (type === "domain") {
    if (value.length > 253) return "Not a valid domain (too long)";
    if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i.test(value)) {
      return "Not a valid domain (expected e.g. example.com)";
    }
    return null;
  }
  if (type === "ip") {
    const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(value);
    if (v4) {
      for (let i = 1; i <= 4; i++) if (parseInt(v4[i], 10) > 255) return "Not a valid IPv4 (octet > 255)";
      return null;
    }
    if (/:/.test(value) && /^[0-9a-f:]+$/i.test(value) && value.length <= 45) return null;
    return "Not a valid IP (expected e.g. 192.0.2.1)";
  }
  if (type === "url") {
    try {
      const u = new URL(value);
      if (u.protocol !== "http:" && u.protocol !== "https:") return "URL must be http:// or https://";
      if (!u.hostname) return "URL must have a host";
      return null;
    } catch { return "Not a valid URL"; }
  }
  return null; // raw: anything goes
}
const MAX_FILE_BYTES = 2 * 1024 * 1024;
const ALLOWED_EXT = new Map([
  [".jpg", "image/jpeg"],
  [".jpeg", "image/jpeg"],
  [".png", "image/png"],
  [".pdf", "application/pdf"],
]);
const SUBMISSION_TYPES = new Set(["domain", "ip", "url", "raw"]);
const THREAT_TYPES = new Set([
  "Spam", "Phishing", "Malware", "Botnet C&C", "Fraud / Scam", "Other",
]);

const BATCHES = new Map();   // id -> batch

function newBatch({ submissionType, threatType, reason, attachment }) {
  const id = crypto.randomBytes(6).toString("hex");
  return {
    id,
    submissionType,
    threatType,
    reason,
    attachment,
    rows: [], // {idx, target, status, confirmation?, error?, attempts}
    createdAt: Date.now(),
  };
}

// -------- worker pool --------
const queue = [];
let active = 0;

function enqueue(task) {
  queue.push(task);
  pump();
}

function pump() {
  while (active < MAX_WORKERS && queue.length > 0) {
    const task = queue.shift();
    active++;
    runTask(task).finally(() => { active--; pump(); });
  }
}

function ts() { return new Date().toISOString().slice(11, 19); }

async function runTask({ batchId, rowIdx }) {
  const batch = BATCHES.get(batchId);
  if (!batch) return;
  const row = batch.rows[rowIdx];
  if (!row) return;
  row.status = "running";
  row.error = null;
  row.attempts = (row.attempts || 0) + 1;
  const tgt = logTarget(row.target);
  log(`[${ts()}] batch=${batchId} row=${rowIdx} target=${tgt} RUNNING (attempt ${row.attempts})`);

  const invalid = validateTarget(batch.submissionType, row.target);
  if (invalid) {
    row.status = "failed";
    row.error = invalid;
    log(`[${ts()}] batch=${batchId} row=${rowIdx} target=${tgt} FAILED ${invalid} (no captcha used)`);
    return;
  }

  try {
    const res = await submitRow({
      submissionType: batch.submissionType,
      target: row.target,
      threatType: batch.threatType,
      reason: batch.reason,
      attachment: batch.attachment,
      captchaApiKey: TWOCAPTCHA_API_KEY,
    });
    if (res.ok) {
      row.status = "success";
      row.confirmation = res.confirmation;
      row.error = null;
      log(`[${ts()}] batch=${batchId} row=${rowIdx} target=${tgt} SUCCESS ${res.confirmation}`);
    } else {
      row.status = "failed";
      row.error = res.error || "Unknown error";
      log(`[${ts()}] batch=${batchId} row=${rowIdx} target=${tgt} FAILED ${row.error}`);
    }
  } catch (e) {
    // submitRow should never throw, but if it does we must not leave the row
    // stuck in "running".
    row.status = "failed";
    row.error = `Unexpected worker error: ${e && e.message ? e.message : String(e)}`;
    log(`[${ts()}] batch=${batchId} row=${rowIdx} target=${tgt} FAILED ${row.error}`);
  }
}

// -------- helpers --------
function send(res, code, body, headers = {}) {
  res.writeHead(code, { "Cache-Control": "no-store", ...headers });
  res.end(body);
}

function sendJson(res, code, obj) {
  send(res, code, JSON.stringify(obj), { "Content-Type": "application/json; charset=utf-8" });
}

function sendFile(res, filePath, contentType) {
  fs.readFile(filePath, (err, data) => {
    if (err) return send(res, 404, "Not found");
    send(res, 200, data, { "Content-Type": contentType });
  });
}

async function readRequestBody(req, limit) {
  return await new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > limit) { req.destroy(); reject(new Error("Body too large")); return; }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function htmlEscape(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function flashRedirect(res, msg) {
  const html = `<!doctype html><meta charset="utf-8">
<title>Validation error</title>
<body style="font:15px system-ui;background:#0b1628;color:#fff;padding:32px">
<div style="max-width:620px;background:#14263f;padding:20px;border-radius:4px">
<p style="color:#ff9b9b;margin:0 0 12px">${htmlEscape(msg)}</p>
<p><a href="/" style="color:#4a8fe7">Back to form</a></p></div></body>`;
  send(res, 400, html, { "Content-Type": "text/html; charset=utf-8" });
}

// -------- routes --------
async function handleStart(req, res) {
  let body;
  try {
    body = await readRequestBody(req, 3 * 1024 * 1024); // 2 MB + slack
  } catch (e) {
    return flashRedirect(res, "Request too large (>3 MB total).");
  }
  const ct = req.headers["content-type"] || "";
  if (!ct.toLowerCase().startsWith("multipart/form-data")) {
    return flashRedirect(res, "Expected multipart/form-data.");
  }
  let parsed;
  try { parsed = parseMultipart(body, ct); }
  catch (e) { return flashRedirect(res, `Malformed form: ${e.message}`); }

  const f = parsed.fields;
  const submissionType = (f.submission_type || "").trim();
  const threatType = (f.threat_type || "").trim();
  const reason = (f.reason || "").trim();
  const targetsRaw = (f.targets || "").trim();

  if (!SUBMISSION_TYPES.has(submissionType)) return flashRedirect(res, "Pick a submission type.");
  if (!THREAT_TYPES.has(threatType)) return flashRedirect(res, "Pick a threat type.");
  if (!reason) return flashRedirect(res, "Reason is required.");

  let targets;
  if (submissionType === "raw") {
    // Raw source is one full email with headers — a single multi-line payload,
    // not a list. The whole textarea becomes exactly one row.
    if (!targetsRaw) return flashRedirect(res, "Paste the email source.");
    targets = [targetsRaw];
  } else {
    targets = targetsRaw.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
    if (targets.length === 0) return flashRedirect(res, "Paste at least one target.");
    if (submissionType === "url") {
      // The target form validates URL with a scheme. Default to https:// if the
      // operator pasted a bare host or path.
      targets = targets.map((t) => (/^[a-z][a-z0-9+.-]*:\/\//i.test(t) ? t : `https://${t}`));
    } else if (submissionType === "domain" || submissionType === "ip") {
      // The target form wants a bare host or IP. Strip any scheme/path/query
      // the operator may have pasted from a browser URL bar.
      targets = targets.map((t) => {
        let s = t.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "");
        s = s.replace(/[\/?#].*$/, "");
        return s;
      });
    }
  }

  let attachment = null;
  const file = parsed.files.attachment;
  if (file && file.filename) {
    const ext = path.extname(file.filename).toLowerCase();
    const mime = ALLOWED_EXT.get(ext);
    if (!mime) return flashRedirect(res, "Attachment must be .jpg, .jpeg, .png or .pdf.");
    if (file.data.length > MAX_FILE_BYTES) return flashRedirect(res, "Attachment must be 2 MB or smaller.");
    attachment = { filename: path.basename(file.filename), contentType: mime, data: file.data };
  }

  const batch = newBatch({ submissionType, threatType, reason, attachment });
  targets.forEach((t, i) => batch.rows.push({ idx: i, target: t, status: "queued", attempts: 0 }));
  BATCHES.set(batch.id, batch);
  log(`[${ts()}] batch=${batch.id} CREATED type=${submissionType} threat="${threatType}" targets=${targets.length}${attachment ? ` attachment=${attachment.filename}(${attachment.data.length}B)` : ""}`);
  for (const row of batch.rows) enqueue({ batchId: batch.id, rowIdx: row.idx });

  send(res, 303, "", { Location: `/batch/${batch.id}` });
}

async function handleRetry(req, res, batchId, rowIdx) {
  const batch = BATCHES.get(batchId);
  if (!batch) return sendJson(res, 404, { ok: false, error: "Batch not found" });
  const row = batch.rows[rowIdx];
  if (!row) return sendJson(res, 404, { ok: false, error: "Row not found" });
  if (row.status === "running") return sendJson(res, 409, { ok: false, error: "Row still running" });
  row.status = "queued";
  row.confirmation = null;
  row.error = null;
  enqueue({ batchId, rowIdx });
  sendJson(res, 200, { ok: true });
}

function handleBatchApi(res, batchId) {
  const batch = BATCHES.get(batchId);
  if (!batch) return sendJson(res, 404, { error: "Not found" });
  const rows = batch.rows.map((r) => ({
    idx: r.idx, target: r.target, status: r.status,
    confirmation: r.confirmation || null, error: r.error || null, attempts: r.attempts || 0,
  }));
  const done = rows.every((r) => r.status === "success" || r.status === "failed");
  sendJson(res, 200, {
    id: batch.id,
    submission_type: batch.submissionType,
    threat_type: batch.threatType,
    attachment_name: batch.attachment ? batch.attachment.filename : null,
    rows, done,
  });
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
    const p = url.pathname;

    if (req.method === "GET" && p === "/") {
      return sendFile(res, path.join(__dirname, "public", "index.html"), "text/html; charset=utf-8");
    }
    const mBatchView = /^\/batch\/([a-f0-9]{6,32})$/.exec(p);
    if (req.method === "GET" && mBatchView) {
      if (!BATCHES.has(mBatchView[1])) return send(res, 404, "Batch not found");
      return sendFile(res, path.join(__dirname, "public", "batch.html"), "text/html; charset=utf-8");
    }
    const mApi = /^\/api\/batch\/([a-f0-9]{6,32})$/.exec(p);
    if (req.method === "GET" && mApi) return handleBatchApi(res, mApi[1]);

    if (req.method === "POST" && p === "/start") return await handleStart(req, res);

    const mRetry = /^\/api\/retry\/([a-f0-9]{6,32})\/(\d+)$/.exec(p);
    if (req.method === "POST" && mRetry) return await handleRetry(req, res, mRetry[1], Number(mRetry[2]));

    send(res, 404, "Not found");
  } catch (e) {
    send(res, 500, `Server error: ${e && e.message ? e.message : e}`);
  }
});

server.listen(PORT, "127.0.0.1", () => {
  log(`[${ts()}] server up on http://127.0.0.1:${PORT}/ (log file: ${LOG_FILE})`);
});
