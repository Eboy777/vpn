export async function verifyDiscoveryDocument(
  document,
  publicKeys,
  {now = Date.now(), previousGeneratedAt = 0, maxStaleSeconds = 604_800} = {},
) {
  validateShape(document);
  const generatedAt = Date.parse(document.generated_at);
  const expiresAt = Date.parse(document.expires_at);
  if (
    !Number.isFinite(generatedAt)
    || !Number.isFinite(expiresAt)
    || generatedAt > now + 300_000
    || expiresAt <= generatedAt
    || expiresAt - generatedAt > 86_400_000
    || expiresAt < now - maxStaleSeconds * 1000
    || generatedAt < previousGeneratedAt
  ) {
    throw new Error("Discovery document time is invalid");
  }
  const publicKey = publicKeys[document.key_id];
  if (!publicKey) throw new Error("Discovery signing key is unknown");
  const key = await crypto.subtle.importKey(
    "raw",
    decodeBase64Url(publicKey),
    {name: "ECDSA", namedCurve: "P-256"},
    false,
    ["verify"],
  );
  const valid = await crypto.subtle.verify(
    {name: "ECDSA", hash: "SHA-256"},
    key,
    decodeBase64Url(document.signature),
    new TextEncoder().encode(canonicalPayload(document)),
  );
  if (!valid) throw new Error("Discovery signature is invalid");
  return Object.freeze({
    ...structuredClone(document),
    control_urls: Object.freeze(document.control_urls.map(normalizeOrigin)),
  });
}

export function normalizeDiscoveryUrls(values) {
  if (!Array.isArray(values) || values.length < 2 || values.length > 20) {
    throw new Error("Discovery requires between 2 and 20 control origins");
  }
  const normalized = values.map(normalizeOrigin);
  if (new Set(normalized).size !== normalized.length) {
    throw new Error("Discovery control origins must be unique");
  }
  return normalized;
}

function validateShape(document) {
  if (!document || typeof document !== "object" || Array.isArray(document)) {
    throw new Error("Discovery document is invalid");
  }
  const expected = [
    "control_urls", "expires_at", "generated_at", "key_id", "signature", "version",
  ];
  if (Object.keys(document).sort().join("|") !== expected.join("|")) {
    throw new Error("Discovery document fields are invalid");
  }
  if (!/^[0-9a-f]{64}$/.test(document.version)) throw new Error("Discovery version is invalid");
  if (!/^[A-Za-z0-9_-]{1,32}$/.test(document.key_id)) throw new Error("Discovery key is invalid");
  if (!/^[A-Za-z0-9_-]{86}$/.test(document.signature)) {
    throw new Error("Discovery signature encoding is invalid");
  }
  normalizeDiscoveryUrls(document.control_urls);
}

function canonicalPayload(document) {
  return JSON.stringify({
    control_urls: document.control_urls,
    expires_at: document.expires_at,
    generated_at: document.generated_at,
    key_id: document.key_id,
    version: document.version,
  });
}

function normalizeOrigin(value) {
  const url = new URL(value);
  if (
    url.protocol !== "https:"
    || url.port && url.port !== "443"
    || url.username
    || url.password
    || url.pathname !== "/"
    || url.search
    || url.hash
  ) {
    throw new Error("Discovery contains an invalid HTTPS origin");
  }
  return url.origin;
}

function decodeBase64Url(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const decoded = atob(normalized + "=".repeat((4 - normalized.length % 4) % 4));
  return Uint8Array.from(decoded, (character) => character.charCodeAt(0));
}
