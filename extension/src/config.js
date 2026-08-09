// This file is part of the signed extension package. Replace the placeholder values only
// during the release build and verify that both origins exactly match PUBLIC_CONTROL_URLS_JSON.
export const BUILD_CONFIG = Object.freeze({
  controlUrls: Object.freeze([
    "https://api-a.example.test",
    "https://api-b.example.test",
  ]),
  requestTimeoutMs: 8_000,
  fallbackDelayMs: 250,
  statusAlarmMinutes: 1,
  controlOfflineGraceSeconds: 300,
  userAgreementUrl: "",
  supportUrl: "",
});

export function validateBuildConfig(config = BUILD_CONFIG) {
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
