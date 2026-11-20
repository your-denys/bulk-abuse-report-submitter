// End-to-end pipeline for one abuse-report submission.
//
//   1. GET  https://linkreclamatiogrwc.uk/            -> session cookie + hidden form_token
//   2. POST https://2captcha.com/in.php               -> task id
//   3. GET  https://2captcha.com/res.php (long-poll)  -> g-recaptcha-response token
//   4. POST https://linkreclamatiogrwc.uk/submit      -> HTML with CF-XXXXXXXX or an error

const TARGET_HOME = "https://linkreclamatiogrwc.uk/";
const TARGET_SUBMIT = "https://linkreclamatiogrwc.uk/submit";
const RECAPTCHA_SITEKEY = "6LfiehouAAAAAFr7759Kztp8FRrwjs0BRxuMZP28";

const UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
  "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36";

const TARGET_FIELD_BY_TYPE = {
  domain: "domain",
  ip: "ip",
  url: "url",
  raw: "raw_source",
};

const CONFIRMATION_RE = /CF-[A-Z0-9]{6,16}/;
const FORM_TOKEN_RE = /name="form_token"\s+value="([^"]+)"/i;
const ALERT_RE = /<div[^>]*class="[^"]*\balert\b[^"]*"[^>]*>([\s\S]*?)<\/div>/i;
const FIELD_ERROR_RE = /<div[^>]*class="[^"]*\bfield-error\b[^"]*"[^>]*>([\s\S]*?)<\/div>/i;

function stripHtml(s) {
  return s
    .replace(/<[^>]+>/g, "")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/\s+/g, " ")
    .trim();
}

function extractError(body) {
  const a = ALERT_RE.exec(body);
  if (a) {
    const t = stripHtml(a[1]);
    if (t) return t;
  }
  const f = FIELD_ERROR_RE.exec(body);
  if (f) {
    const t = stripHtml(f[1]);
    if (t) return t;
  }
  return "Form rejected (no visible error on page)";
}

// Pull Set-Cookie values into a single Cookie header for the next request.
function cookiesFromHeaders(headers) {
  const raw = [];
  // Node's fetch exposes raw Set-Cookie via getSetCookie() on undici >= 6.
  if (typeof headers.getSetCookie === "function") {
    raw.push(...headers.getSetCookie());
  } else {
    const sc = headers.get("set-cookie");
    if (sc) raw.push(sc);
  }
  const jar = [];
  for (const line of raw) {
    const nv = line.split(";", 1)[0];
    if (nv) jar.push(nv.trim());
  }
  return jar.join("; ");
}

async function fetchFormContext() {
  const r = await fetch(TARGET_HOME, { headers: { "User-Agent": UA }, redirect: "follow" });
  if (!r.ok) throw new Error(`GET / HTTP ${r.status}`);
  const body = await r.text();
  const m = FORM_TOKEN_RE.exec(body);
  if (!m) throw new Error("form_token not found on page");
  return { cookieHeader: cookiesFromHeaders(r.headers), formToken: m[1] };
}

async function solveRecaptchaV2(apiKey, { timeoutMs = 180_000, pollMs = 5_000 } = {}) {
  const inUrl = new URL("https://2captcha.com/in.php");
  const inBody = new URLSearchParams({
    key: apiKey,
    method: "userrecaptcha",
    googlekey: RECAPTCHA_SITEKEY,
    pageurl: TARGET_HOME,
    json: "1",
  });
  const inRes = await fetch(inUrl, { method: "POST", body: inBody });
  if (!inRes.ok) throw new Error(`2captcha in.php HTTP ${inRes.status}`);
  const inJson = await inRes.json();
  if (inJson.status !== 1) throw new Error(`2captcha rejected task: ${inJson.request}`);
  const taskId = inJson.request;

  const deadline = Date.now() + timeoutMs;
  await new Promise((r) => setTimeout(r, 10_000));
  while (Date.now() < deadline) {
    const resUrl = new URL("https://2captcha.com/res.php");
    resUrl.search = new URLSearchParams({
      key: apiKey, action: "get", id: taskId, json: "1",
    }).toString();
    const r = await fetch(resUrl);
    if (!r.ok) throw new Error(`2captcha res.php HTTP ${r.status}`);
    const j = await r.json();
    if (j.status === 1) return j.request;
    if (j.request !== "CAPCHA_NOT_READY") throw new Error(`2captcha error: ${j.request}`);
    await new Promise((r) => setTimeout(r, pollMs));
  }
  throw new Error(`2captcha timed out after ${timeoutMs} ms`);
}

/**
 * Submit one row. Never throws — returns {ok, confirmation?, error?}.
 *
 * @param {object} args
 * @param {"domain"|"ip"|"url"|"raw"} args.submissionType
 * @param {string} args.target
 * @param {string} args.threatType
 * @param {string} args.reason
 * @param {{filename:string, contentType:string, data:Buffer}|null} args.attachment
 * @param {string} args.captchaApiKey
 */
export async function submitRow({
  submissionType, target, threatType, reason, attachment, captchaApiKey,
}) {
  try {
    const targetField = TARGET_FIELD_BY_TYPE[submissionType];
    if (!targetField) return { ok: false, error: `Unknown submission_type: ${submissionType}` };

    const { cookieHeader, formToken } = await fetchFormContext();
    const captchaToken = await solveRecaptchaV2(captchaApiKey);

    const form = new FormData();
    form.set("form_token", formToken);
    form.set("submission_type", submissionType);
    form.set(targetField, target);
    form.set("threat_type", threatType);
    form.set("reason", reason);
    form.set("accept_terms", "1");
    form.set("g-recaptcha-response", captchaToken);
    if (attachment) {
      form.set(
        "attachment",
        new Blob([attachment.data], { type: attachment.contentType || "application/octet-stream" }),
        attachment.filename,
      );
    }

    const r = await fetch(TARGET_SUBMIT, {
      method: "POST",
      body: form,
      headers: {
        "User-Agent": UA,
        Referer: TARGET_HOME,
        ...(cookieHeader ? { Cookie: cookieHeader } : {}),
      },
      redirect: "follow",
    });
    const body = await r.text();
    const m = CONFIRMATION_RE.exec(body);
    if (m) return { ok: true, confirmation: m[0] };
    if (r.status >= 400) return { ok: false, error: `HTTP ${r.status}: ${extractError(body)}` };
    return { ok: false, error: extractError(body) };
  } catch (e) {
    return { ok: false, error: e && e.message ? e.message : String(e) };
  }
}
