const ALLOWED_EXTERNAL_PROTOCOLS = new Set(["http:", "https:"]);

export function safeExternalUrl(value) {
  const raw = String(value ?? "").trim();
  if (!raw || raw.length > 4096 || /[\u0000-\u001f\u007f\\]/u.test(raw)) return "";

  try {
    const url = new URL(raw);
    if (!ALLOWED_EXTERNAL_PROTOCOLS.has(url.protocol)) return "";
    if (!url.hostname || url.username || url.password) return "";
    return url.href;
  } catch (error) {
    return "";
  }
}
