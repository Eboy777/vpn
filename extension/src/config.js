// This file is part of the signed extension package. Replace the placeholder values only
// during the release build and verify that both origins exactly match PUBLIC_CONTROL_URLS_JSON.
export const BUILD_CONFIG = Object.freeze({
  controlUrls: Object.freeze([
    "https://api-a.example.test",
    "https://api-b.example.test",
  ]),
  discoveryPublicKeys: Object.freeze({
    // Development-only P-256 public key. Replace together with controlUrls for release.
    v1: "BGsX0fLhLEJH-Lzm5WOkQPJ3A32BLeszoPShOUXYmMKWT-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU",
  }),
  discoveryRefreshSeconds: 900,
  discoveryMaxStaleSeconds: 604_800,
  requestTimeoutMs: 8_000,
  fallbackDelayMs: 250,
  statusAlarmMinutes: 1,
  controlOfflineGraceSeconds: 300,
  userAgreementUrl: "",
  supportUrl: "",
});

export function validateBuildConfig(config = BUILD_CONFIG) {
  config = {...BUILD_CONFIG, ...config};
  if (!Array.isArray(config.controlUrls) || config.controlUrls.length !== 2) {
    throw new Error("Virgo requires exactly two control API origins");
  }

  const parsed = config.controlUrls.map((value) => {
    const url = new URL(value);
    if (
      url.protocol !== "https:"
      || url.port && url.port !== "443"
      || url.username
      || url.password
      || url.search
      || url.hash
    ) {
      throw new Error("Control API URLs must be plain HTTPS origins");
    }
    if (url.pathname !== "/") {
      throw new Error("Control API URLs must not contain a path");
    }
    return url;
  });
  const normalized = parsed.map((url) => url.origin);

  if (new Set(normalized).size !== 2 || new Set(parsed.map((url) => url.hostname)).size !== 2) {
    throw new Error("Control API origins and hostnames must be distinct");
  }
  if (
    !Number.isInteger(config.controlOfflineGraceSeconds)
    || config.controlOfflineGraceSeconds < 60
    || config.controlOfflineGraceSeconds > 3600
  ) {
    throw new Error("Control API offline grace must be between 60 and 3600 seconds");
  }
  if (
    !config.discoveryPublicKeys
    || Object.keys(config.discoveryPublicKeys).length < 1
    || Object.values(config.discoveryPublicKeys).some(
      (value) => !/^[A-Za-z0-9_-]{87}$/.test(value),
    )
  ) {
    throw new Error("At least one P-256 discovery public key is required");
  }
  if (
    !Number.isInteger(config.discoveryRefreshSeconds)
    || config.discoveryRefreshSeconds < 300
    || config.discoveryRefreshSeconds > 86_400
    || !Number.isInteger(config.discoveryMaxStaleSeconds)
    || config.discoveryMaxStaleSeconds < config.discoveryRefreshSeconds
  ) {
    throw new Error("Discovery refresh and stale limits are invalid");
  }
  for (const [name, value] of [
    ["userAgreementUrl", config.userAgreementUrl],
    ["supportUrl", config.supportUrl],
  ]) {
    if (value && new URL(value).protocol !== "https:") {
      throw new Error(`${name} must use HTTPS`);
    }
  }
  return Object.freeze({...config, controlUrls: Object.freeze(normalized)});
}

export function controlHostnames(config = BUILD_CONFIG) {
  return validateBuildConfig(config).controlUrls.map((value) => new URL(value).hostname);
}
