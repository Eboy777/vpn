const STORAGE_KEY = "virgoStateV1";

export function initialState(deviceId = crypto.randomUUID()) {
  return {
    schemaVersion: 1,
    deviceId,
    deviceToken: null,
    pairing: null,
    vpnEnabled: false,
    connectedAt: null,
    vpnSessionId: null,
    connectionAttemptStartedAt: null,
    hadSuccessfulConnection: false,
    lastTelemetryErrorAt: 0,
    status: null,
    currentProxy: null,
    controlRateLimitedUntil: 0,
    controlUnavailableSince: null,
    nextStatusCheckAt: 0,
    discoveryDocument: null,
    discoveryRefreshAt: 0,
    lastError: null,
  };
}

export function createStateStore(storageArea = chrome.storage.local) {
  return {
    async read() {
      const stored = (await storageArea.get(STORAGE_KEY))[STORAGE_KEY];
      if (!isState(stored)) {
        const created = initialState();
        await storageArea.set({[STORAGE_KEY]: created});
        return created;
      }
      return {
        ...structuredClone(stored),
        controlRateLimitedUntil: Number(stored.controlRateLimitedUntil) || 0,
        controlUnavailableSince: Number(stored.controlUnavailableSince) || null,
        nextStatusCheckAt: Number(stored.nextStatusCheckAt) || 0,
        connectionAttemptStartedAt: Number(stored.connectionAttemptStartedAt) || null,
        hadSuccessfulConnection: Boolean(stored.hadSuccessfulConnection),
        discoveryDocument: stored.discoveryDocument && typeof stored.discoveryDocument === "object"
          ? structuredClone(stored.discoveryDocument)
          : null,
        discoveryRefreshAt: Number(stored.discoveryRefreshAt) || 0,
      };
    },

    async write(nextState) {
      if (!isState(nextState)) {
        throw new Error("Refusing to persist an invalid extension state");
      }
      await storageArea.set({[STORAGE_KEY]: structuredClone(nextState)});
      return nextState;
    },

    async update(mutator) {
      const current = await this.read();
      const next = (await mutator(structuredClone(current))) ?? current;
      return this.write(next);
    },

    async reset({controlRateLimitedUntil = 0} = {}) {
      const current = await this.read();
      const reset = {
        ...initialState(),
        controlRateLimitedUntil,
        discoveryDocument: current.discoveryDocument,
        discoveryRefreshAt: current.discoveryRefreshAt,
      };
      await storageArea.set({[STORAGE_KEY]: reset});
      return reset;
    },
  };
}

export function publicView(state, extensionVersion = "1.0.0") {
  const status = state.status ? structuredClone(state.status) : null;
  if (status?.vpn) {
    delete status.vpn.credentials;
  }
  return {
    paired: Boolean(state.deviceToken),
    pairing: state.pairing && {
      telegramUrl: state.pairing.telegramUrl,
      expiresAt: state.pairing.expiresAt,
      pollAfterSeconds: state.pairing.pollAfterSeconds,
    },
    vpnEnabled: state.vpnEnabled,
    proxyActive: Boolean(state.vpnEnabled && state.currentProxy),
    connectedAt: state.connectedAt,
    status,
    lastError: state.lastError,
    extensionVersion,
  };
}

function isState(value) {
  return Boolean(
    value
      && value.schemaVersion === 1
      && typeof value.deviceId === "string"
      && (value.deviceToken === null || typeof value.deviceToken === "string")
      && typeof value.vpnEnabled === "boolean",
  );
}
