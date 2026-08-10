import {ControlApiClient, ControlApiError} from "./src/api-client.js";
import {BUILD_CONFIG, controlHostnames, validateBuildConfig} from "./src/config.js";
import {
  createProxyController,
  isCurrentProxyChallenge,
  proxyFromStatus,
} from "./src/proxy-controller.js";
import {createStateStore, publicView} from "./src/storage.js";
import {shouldDisableProxy} from "./src/safety.js";

const CONFIG = validateBuildConfig(BUILD_CONFIG);
const STATUS_ALARM = "virgo-status-refresh";
const store = createStateStore();
const api = new ControlApiClient({
  config: CONFIG,
  getRateLimitedUntil: async () => (await store.read()).controlRateLimitedUntil,
  setRateLimitedUntil: async (value) => {
    await store.update((state) => ({...state, controlRateLimitedUntil: value}));
  },
});
const proxyController = createProxyController();
const authAttempts = new Set();
let refreshPromise = null;
let operationQueue = Promise.resolve();

chrome.runtime.onInstalled.addListener((details) => {
  const eventType = details.reason === "install" ? "installed" : "updated";
  void enqueueOperation(async () => {
    await reportLifecycle(eventType).catch(() => undefined);
    await bootstrap();
  });
});

chrome.runtime.onStartup.addListener(() => {
  void enqueueOperation(async () => {
    await reportLifecycle("launched").catch(() => undefined);
    await bootstrap();
  });
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === STATUS_ALARM) {
    void enqueueOperation(() => refreshStatus({force: false})).catch(() => undefined);
  }
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  enqueueOperation(() => handleMessage(message))
    .then((value) => sendResponse({ok: true, value}))
    .catch((error) => sendResponse({ok: false, error: userFacingError(error)}));
  return true;
});

chrome.webRequest.onAuthRequired.addListener(
  (details, callback) => {
    provideProxyCredentials(details)
      .then(callback)
      .catch(() => callback({cancel: true}));
  },
  {urls: ["<all_urls>"]},
  ["asyncBlocking"],
);

chrome.webRequest.onCompleted.addListener(
  (details) => authAttempts.delete(details.requestId),
  {urls: ["<all_urls>"]},
);

chrome.webRequest.onErrorOccurred.addListener(
  (details) => {
    authAttempts.delete(details.requestId);
    try {
      if (controlHostnames(CONFIG).includes(new URL(details.url).hostname)) return;
    } catch {
      return;
    }
    void enqueueOperation(reportConnectionError).catch(() => undefined);
  },
  {urls: ["<all_urls>"]},
);

void enqueueOperation(bootstrap);

function enqueueOperation(operation) {
  const current = operationQueue.then(operation, operation);
  operationQueue = current.catch(() => undefined);
  return current;
}

async function bootstrap() {
  const state = await store.read();
  if (state.vpnEnabled && state.deviceToken) {
    if (state.nextStatusCheckAt <= Date.now()) {
      await refreshStatus({force: false}).catch(() => enforceLocalSafetyDeadline());
    } else {
      await ensureStatusAlarm(state);
      await enforceLocalSafetyDeadline();
    }
  } else {
    await chrome.alarms.clear(STATUS_ALARM);
    if (state.currentProxy) {
      await proxyController.disable();
      await store.update((current) => ({
        ...current,
        currentProxy: null,
        connectedAt: null,
        nextStatusCheckAt: 0,
      }));
    }
  }
  await updateBadge(await store.read());
}

async function handleMessage(message) {
  if (!message || typeof message.type !== "string") {
    throw new Error("Некорректная команда расширения");
  }
  switch (message.type) {
    case "GET_VIEW":
      return view();
    case "START_PAIRING":
      await startPairing();
      return view();
    case "POLL_PAIRING":
      await pollPairing();
      return view();
    case "SET_VPN":
      await setVpn(Boolean(message.enabled));
      return view();
    case "REFRESH_STATUS":
      await refreshStatus({force: true});
      return view();
    case "SELECT_NODE":
      await selectNode(message.nodeId ?? null);
      return view();
    case "GET_NODES":
      return getNodes();
    case "TRACK_EVENT":
      if (message.eventType !== "tariff_viewed") throw new Error("Некорректное событие");
      await reportVpnEvent("tariff_viewed");
      return null;
    case "LOGOUT":
      await logout();
      return view();
    default:
      throw new Error("Неизвестная команда расширения");
  }
}

async function view() {
  const state = await store.read();
  return publicView(state, chrome.runtime.getManifest().version);
}

async function startPairing() {
  const state = await store.read();
  if (state.deviceToken) return;
  const result = await api.pairingInit(state.deviceId);
  await store.write({
    ...state,
    pairing: {
      pairingSessionToken: result.pairing_session_token,
      telegramUrl: result.telegram_url,
      expiresAt: result.expires_at,
      pollAfterSeconds: result.poll_after_seconds,
    },
    lastError: null,
  });
}

async function pollPairing() {
  const state = await store.read();
  if (!state.pairing || state.deviceToken) return;
  const result = await api.pairingStatus(
    state.deviceId,
    state.pairing.pairingSessionToken,
  );
  if (result.status !== "paired") {
    await store.write({
      ...state,
      pairing: {
        ...state.pairing,
        expiresAt: result.expires_at,
        pollAfterSeconds: result.poll_after_seconds,
      },
      lastError: null,
    });
    return;
  }

  await store.write({
    ...state,
    deviceToken: result.device_token,
    pairing: null,
    lastError: null,
  });
  await refreshStatus({force: true});
}

async function setVpn(enabled) {
  const state = await store.read();
  if (!state.deviceToken) throw new Error("Сначала привяжите Telegram");
  if (!enabled) {
    await reportVpnEvent("vpn_stopped").catch(() => undefined);
    await proxyController.disable();
    await chrome.alarms.clear(STATUS_ALARM);
    const next = await store.write({
      ...state,
      vpnEnabled: false,
      connectedAt: null,
      currentProxy: null,
      vpnSessionId: null,
      connectionAttemptStartedAt: null,
      hadSuccessfulConnection: false,
      controlUnavailableSince: null,
      nextStatusCheckAt: 0,
      lastError: null,
    });
    await updateBadge(next);
    return;
  }

  const attempt = await store.write({
    ...state,
    vpnEnabled: true,
    vpnSessionId: state.vpnSessionId || crypto.randomUUID(),
    connectionAttemptStartedAt: Date.now(),
    controlUnavailableSince: null,
    nextStatusCheckAt: 0,
    lastError: null,
  });
  await reportVpnEvent("connection_attempt", attempt).catch(() => undefined);
  try {
    await refreshStatus({force: true});
  } catch (error) {
    const failed = await store.read();
    const durationMs = Math.max(0, Date.now() - Number(failed.connectionAttemptStartedAt || Date.now()));
    await reportVpnEvent(
      "connection_error",
      failed,
      telemetryErrorCode(error),
      durationMs,
    ).catch(() => undefined);
    throw error;
  }
}

async function refreshStatus({force = false} = {}) {
  if (refreshPromise) return refreshPromise;
  refreshPromise = performStatusRefresh({force}).finally(() => {
    refreshPromise = null;
  });
  return refreshPromise;
}

async function performStatusRefresh({force}) {
  const state = await store.read();
  const refreshStartedAt = Date.now();
  if (!state.deviceToken) return state;
  if (!force && state.nextStatusCheckAt > Date.now()) {
    await ensureStatusAlarm(state);
    return state;
  }
  try {
    const status = await api.status(state.deviceToken);
    validateStatusBypass(status);
    const nextCheckSeconds = Math.max(60, Number(status.next_check_seconds) || 60);
    let next = {
      ...state,
      status,
      controlUnavailableSince: null,
      nextStatusCheckAt: Date.now() + nextCheckSeconds * 1000,
      lastError: null,
    };
    const newProxy = proxyFromStatus(status);
    const nodeChanged = Boolean(
      state.vpnEnabled
      && state.currentProxy?.nodeId
      && newProxy?.nodeId
      && state.currentProxy.nodeId !== newProxy.nodeId,
    );
    const reconnecting = Boolean(
      state.vpnEnabled && state.hadSuccessfulConnection && !state.currentProxy && newProxy,
    );
    if (state.vpnEnabled && newProxy) {
      next = {
        ...next,
        vpnSessionId: state.vpnSessionId || crypto.randomUUID(),
        currentProxy: newProxy,
        connectedAt: state.connectedAt ?? Date.now(),
        hadSuccessfulConnection: true,
      };
      try {
        // Persist credentials first so onAuthRequired can answer immediately after settings flip.
        await store.write(next);
        await proxyController.enable(newProxy, newProxy.bypassList);
      } catch (error) {
        await store.write(state).catch(() => undefined);
        await restoreStoredProxy(state).catch(() => undefined);
        throw error;
      }
    } else if (!newProxy) {
      if (state.vpnSessionId) {
        await reportVpnEvent("vpn_stopped", state).catch(() => undefined);
      }
      await proxyController.disable();
      const finalAccessState = ["expired", "blocked"].includes(status.access?.state);
      next = {
        ...next,
        vpnEnabled: finalAccessState ? false : state.vpnEnabled,
        currentProxy: null,
        connectedAt: null,
        vpnSessionId: null,
        connectionAttemptStartedAt: null,
      };
      if (finalAccessState) await chrome.alarms.clear(STATUS_ALARM);
    }
    let saved;
    try {
      saved = state.vpnEnabled && newProxy ? next : await store.write(next);
    } catch (error) {
      await restoreStoredProxy(state).catch(() => undefined);
      throw error;
    }
    if (saved.vpnEnabled) await scheduleStatusAlarm(nextCheckSeconds);
    if (saved.vpnEnabled && newProxy) {
      const eventType = state.connectedAt === null ? "vpn_started" : "vpn_heartbeat";
      const durationMs = Math.max(
        0,
        Date.now() - Number(state.connectionAttemptStartedAt || refreshStartedAt),
      );
      if (nodeChanged) {
        await reportVpnEvent("node_failover", saved, null, durationMs).catch(() => undefined);
      } else if (reconnecting) {
        await reportVpnEvent("reconnect", saved, null, durationMs).catch(() => undefined);
      }
      await reportVpnEvent(eventType, saved, null, eventType === "vpn_started" ? durationMs : null)
        .catch(() => undefined);
      if (saved.connectionAttemptStartedAt !== null) {
        saved = await store.update((current) => ({
          ...current,
          connectionAttemptStartedAt: null,
        }));
      }
    }
    await updateBadge(saved);
    return saved;
  } catch (error) {
    if (error instanceof ControlApiError && error.status === 401) {
      await logout();
    } else {
      const retrySeconds = Math.max(60, Number(error?.retryAfterSeconds) || 60);
      const failed = await store.update((current) => ({
        ...current,
        controlUnavailableSince: current.controlUnavailableSince ?? Date.now(),
        nextStatusCheckAt: Date.now() + retrySeconds * 1000,
        lastError: userFacingError(error),
      }));
      if (failed.vpnEnabled) await scheduleStatusAlarm(retrySeconds);
      await enforceLocalSafetyDeadline();
    }
    throw error;
  }
}

async function restoreStoredProxy(state) {
  if (state.vpnEnabled && state.currentProxy) {
    await proxyController.enable(state.currentProxy, state.currentProxy.bypassList);
  } else {
    await proxyController.disable();
  }
}

async function enforceLocalSafetyDeadline() {
  const state = await store.read();
  if (!shouldDisableProxy({
    now: Date.now(),
    accessExpiresAt: state.status?.access?.access_expires_at,
    controlUnavailableSince: state.controlUnavailableSince,
    controlOfflineGraceSeconds: CONFIG.controlOfflineGraceSeconds,
  })) return;
  await proxyController.disable();
  await chrome.alarms.clear(STATUS_ALARM);
  const next = await store.write({
    ...state,
    vpnEnabled: false,
    currentProxy: null,
    vpnSessionId: null,
    connectionAttemptStartedAt: null,
    connectedAt: null,
    nextStatusCheckAt: 0,
  });
  await updateBadge(next);
}

async function reportLifecycle(eventType) {
  const state = await store.read();
  const context = await clientTelemetryContext();
  return api.lifecycle({
    event_id: crypto.randomUUID(),
    installation_id: state.deviceId,
    event_type: eventType,
    extension_version: chrome.runtime.getManifest().version,
    ...context,
  });
}

async function reportVpnEvent(
  eventType,
  providedState = null,
  errorCode = null,
  durationMs = null,
) {
  const state = providedState || await store.read();
  if (!state.deviceToken || (eventType !== "tariff_viewed" && !state.vpnSessionId)) return;
  const context = await clientTelemetryContext();
  await api.telemetry(state.deviceToken, {
    event_id: crypto.randomUUID(),
    event_type: eventType,
    ...(state.vpnSessionId ? {session_id: state.vpnSessionId} : {}),
    extension_version: chrome.runtime.getManifest().version,
    ...context,
    ...(errorCode ? {error_code: errorCode} : {}),
    ...(durationMs === null ? {} : {duration_ms: Math.min(300_000, Math.round(durationMs))}),
  });
}

async function clientTelemetryContext() {
  const platformInfo = await chrome.runtime.getPlatformInfo().catch(() => ({os: "unknown"}));
  const brands = globalThis.navigator?.userAgentData?.brands || [];
  const preferred = brands.find((item) => !String(item.brand).includes("Not")) || null;
  const userAgent = String(globalThis.navigator?.userAgent || "");
  const fallback = userAgent.match(/(?:Chrome|Chromium)\/([0-9.]+)/);
  return {
    browser_name: normalizeTelemetryLabel(preferred?.brand || "chromium"),
    browser_version: normalizeTelemetryLabel(preferred?.version || fallback?.[1] || "unknown"),
    platform: normalizeTelemetryLabel(platformInfo.os || "unknown"),
  };
}

function normalizeTelemetryLabel(value) {
  const normalized = String(value).replace(/[^0-9A-Za-z._-]/g, "_").slice(0, 32);
  return normalized || "unknown";
}

function telemetryErrorCode(error) {
  const code = String(error?.code || "CONNECTION_FAILED").toUpperCase();
  return code.replace(/[^A-Z0-9_]/g, "_").slice(0, 64) || "CONNECTION_FAILED";
}

async function reportConnectionError() {
  const state = await store.read();
  if (!state.vpnEnabled || !state.vpnSessionId) return;
  const now = Date.now();
  if (now - Number(state.lastTelemetryErrorAt || 0) < 60_000) return;
  const next = await store.write({...state, lastTelemetryErrorAt: now});
  await reportVpnEvent("connection_error", next, "PROXY_REQUEST_FAILED");
}

async function getNodes() {
  const state = await store.read();
  if (!state.deviceToken) throw new Error("Устройство не привязано");
  return api.nodes(state.deviceToken);
}

async function selectNode(nodeId) {
  const state = await store.read();
  if (!state.deviceToken) throw new Error("Устройство не привязано");
  await api.selectNode(state.deviceToken, nodeId);
  await refreshStatus({force: true});
}

async function logout() {
  const controlRateLimitedUntil = (await store.read()).controlRateLimitedUntil;
  await reportVpnEvent("vpn_stopped").catch(() => undefined);
  await proxyController.disable();
  await chrome.alarms.clear(STATUS_ALARM);
  authAttempts.clear();
  const reset = await store.reset({controlRateLimitedUntil});
  await updateBadge(reset);
}

async function provideProxyCredentials(details) {
  const state = await store.read();
  if (!state.vpnEnabled || !isCurrentProxyChallenge(details, state.currentProxy)) {
    return {};
  }
  if (authAttempts.has(details.requestId)) {
    return {cancel: true};
  }
  authAttempts.add(details.requestId);
  return {
    authCredentials: {
      username: state.currentProxy.username,
      password: state.currentProxy.password,
    },
  };
}

async function ensureStatusAlarm(state) {
  const existing = await chrome.alarms.get(STATUS_ALARM);
  if (!existing) {
    const seconds = Math.max(60, Math.ceil((state.nextStatusCheckAt - Date.now()) / 1000));
    await scheduleStatusAlarm(seconds);
  }
}

async function scheduleStatusAlarm(delaySeconds) {
  const delayInMinutes = Math.max(
    CONFIG.statusAlarmMinutes,
    Math.ceil(delaySeconds / 60),
  );
  await chrome.alarms.create(STATUS_ALARM, {delayInMinutes});
}

function validateStatusBypass(status) {
  const expected = controlHostnames(CONFIG);
  const received = status?.vpn?.bypass_list;
  if (!Array.isArray(received) || JSON.stringify(received) !== JSON.stringify(expected)) {
    throw new Error("Backend вернул неверный список обхода control API");
  }
}

async function updateBadge(state) {
  const active = Boolean(state.vpnEnabled && state.currentProxy);
  await chrome.action.setBadgeText({text: active ? "ON" : ""});
  if (active) await chrome.action.setBadgeBackgroundColor({color: "#20d26b"});
}

function userFacingError(error) {
  if (error instanceof ControlApiError) {
    const messages = {
      ACCESS_EXPIRED: "Доступ закончился. Продлите подписку.",
      DEVICE_LIMIT_REACHED: "Достигнут лимит устройств.",
      DEVICE_REVOKED: "Это устройство было отключено.",
      NO_ACTIVE_NODE: "Сейчас нет доступных VPN-серверов.",
      PAIRING_EXPIRED: "Время привязки истекло. Начните заново.",
      RATE_LIMITED: "Слишком много запросов. Попробуйте чуть позже.",
      USER_BLOCKED: "Доступ к аккаунту заблокирован.",
    };
    return messages[error.code] || "Не удалось связаться с Virgo. Повторите попытку.";
  }
  return error instanceof Error && error.message
    ? error.message
    : "Произошла неизвестная ошибка.";
}
