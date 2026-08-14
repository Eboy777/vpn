// This file is part of the signed extension package. Both origins must exactly match
// PUBLIC_CONTROL_URLS_JSON in their intended failover order.
export const BUILD_CONFIG = Object.freeze({
  controlUrls: Object.freeze([
    "https://invalid-control.virgo-vpn.site",
    "https://api.virgo-vpn.site",
  ]),
  discoveryPublicKeys: Object.freeze({
    v1: "BCyntUK8FshqXbTTN-Xg29En0nUhlwMrtJuv7Dkg6G50wwEIFcpx8vhPQZDAlDsF0Ut1ReiabuWOkh_7G2fQKco",
  }),
  discoveryRefreshSeconds: 900,
  discoveryMaxStaleSeconds: 604_800,
  requestTimeoutMs: 8_000,
  fallbackDelayMs: 250,
  statusAlarmMinutes: 1,
  controlOfflineGraceSeconds: 300,
  userAgreementUrl: "",
  telegramBotUrl: "https://t.me/virgo1vpn_bot",
  telegramSupportUrl: "https://t.me/virgo1vpn_bot?start=support",
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
    ["telegramBotUrl", config.telegramBotUrl],
    ["telegramSupportUrl", config.telegramSupportUrl],
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
