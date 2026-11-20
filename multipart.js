// Minimal multipart/form-data parser for the single incoming form.
// Scope: plain text fields + one optional file. Not a general-purpose parser.

export function parseMultipart(buffer, contentType) {
  const m = /boundary=(?:"([^"]+)"|([^;]+))/i.exec(contentType || "");
  if (!m) throw new Error("multipart: no boundary");
  const boundary = Buffer.from("--" + (m[1] || m[2]).trim());
  const crlf = Buffer.from("\r\n");

  const parts = [];
  let i = buffer.indexOf(boundary);
  if (i < 0) throw new Error("multipart: boundary not found");
  i += boundary.length;

  while (i < buffer.length) {
    // after a boundary we either have "--" (end) or "\r\n" (another part)
    if (buffer[i] === 0x2d && buffer[i + 1] === 0x2d) break;
    if (buffer[i] === 0x0d && buffer[i + 1] === 0x0a) i += 2;
    const headerEnd = buffer.indexOf(Buffer.from("\r\n\r\n"), i);
    if (headerEnd < 0) break;
    const headers = buffer.slice(i, headerEnd).toString("utf8");
    const bodyStart = headerEnd + 4;
    const next = buffer.indexOf(boundary, bodyStart);
    if (next < 0) break;
    // part body ends at the CRLF just before the next boundary
    const bodyEnd = next - 2;
    const body = buffer.slice(bodyStart, bodyEnd);

    const disp = /content-disposition:[^\n]*name="([^"]+)"(?:;\s*filename="([^"]*)")?/i.exec(headers);
    const ctype = /content-type:\s*([^\r\n]+)/i.exec(headers);
    if (disp) {
      parts.push({
        name: disp[1],
        filename: disp[2] || null,
        contentType: ctype ? ctype[1].trim() : null,
        data: body,
      });
    }
    i = next + boundary.length;
  }

  const fields = {};
  const files = {};
  for (const p of parts) {
    if (p.filename !== null) {
      files[p.name] = { filename: p.filename, contentType: p.contentType, data: p.data };
    } else {
      fields[p.name] = p.data.toString("utf8");
    }
  }
  return { fields, files };
}
