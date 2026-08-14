export function shouldDisableProxy({
  now,
  accessExpiresAt,
  accessSafetyDeadline = null,
  controlUnavailableSince,
  controlOfflineGraceSeconds,
  accessSafetyMarginSeconds = 5,
}) {
  const parsedExpiry = Date.parse(accessExpiresAt || "");
  const accessDeadline = Number.isFinite(accessSafetyDeadline)
    ? accessSafetyDeadline
    : Number.isFinite(parsedExpiry)
      ? parsedExpiry - accessSafetyMarginSeconds * 1000
      : Number.POSITIVE_INFINITY;
  const offlineDeadline = controlUnavailableSince
    ? controlUnavailableSince + controlOfflineGraceSeconds * 1000
    : Number.POSITIVE_INFINITY;
  return Math.min(accessDeadline, offlineDeadline) <= now;
}
