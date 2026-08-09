export function shouldDisableProxy({
  now,
  accessExpiresAt,
  controlUnavailableSince,
  controlOfflineGraceSeconds,
}) {
  const parsedExpiry = Date.parse(accessExpiresAt || "");
  const accessDeadline = Number.isFinite(parsedExpiry)
    ? parsedExpiry
    : Number.POSITIVE_INFINITY;
  const offlineDeadline = controlUnavailableSince
    ? controlUnavailableSince + controlOfflineGraceSeconds * 1000
    : Number.POSITIVE_INFINITY;
  return Math.min(accessDeadline, offlineDeadline) <= now;
}
