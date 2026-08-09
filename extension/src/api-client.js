import {BUILD_CONFIG, validateBuildConfig} from "./config.js";

const RETRYABLE_STATUS = new Set([408, 502, 503, 504]);

export class ControlApiError extends Error {
  constructor(message, {status = 0, code = "NETWORK_ERROR", retryAfterSeconds = null} = {}) {
    super(message);
    this.name = "ControlApiError";
    this.status = status;
    this.code = code;
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

export class ControlApiClient {
  constructor({
    config = BUILD_CONFIG,
    fetchImpl = globalThis.fetch?.bind(globalThis),
    randomUUID = () => crypto.randomUUID(),
    sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)),
    now = () => Date.now(),
    getRateLimitedUntil = null,
    setRateLimitedUntil = null,
  } = {}) {
    this.config = validateBuildConfig(config);
    if (typeof fetchImpl !== "function") {
      throw new Error("fetch is unavailable");
    }
    this.fetchImpl = fetchImpl;
    this.randomUUID = randomUUID;
    this.sleep = sleep;
    this.now = now;
    this.rateLimitedUntil = 0;
    this.getRateLimitedUntil = getRateLimitedUntil
      ?? (async () => this.rateLimitedUntil);
    this.setRateLimitedUntil = setRateLimitedUntil
      ?? (async (value) => { this.rateLimitedUntil = value; });
  }

  pairingInit(deviceId) {
    return this.request("/api/pairing/init", {
      method: "POST",
      body: {device_id: deviceId},
    });
  }

  pairingStatus(deviceId, pairingSessionToken) {
    const query = new URLSearchParams({device_id: deviceId});
    return this.request(`/api/pairing/status?${query}`, {
      token: pairingSessionToken,
    });
  }

  status(deviceToken) {
    return this.request("/api/status", {token: deviceToken});
  }

  nodes(deviceToken) {
    return this.request("/api/nodes", {token: deviceToken});
  }

  selectNode(deviceToken, nodeId) {
    return this.request("/api/nodes/select", {
      method: "POST",
      token: deviceToken,
      body: {node_id: nodeId},
    });
  }

  async request(path, {method = "GET", token = null, body = undefined} = {}) {
    if (!path.startsWith("/")) {
      throw new Error("API path must be absolute");
    }
    const rateLimitedUntil = Math.max(this.rateLimitedUntil, await this.getRateLimitedUntil());
    if (rateLimitedUntil > this.now()) {
      const seconds = Math.max(1, Math.ceil((rateLimitedUntil - this.now()) / 1000));
      throw new ControlApiError("Too many requests", {
        status: 429,
        code: "RATE_LIMITED",
        retryAfterSeconds: seconds,
      });
    }

    const requestId = this.randomUUID();
    let lastError = null;
    for (let index = 0; index < this.config.controlUrls.length; index += 1) {
      if (index > 0) {
        await this.sleep(this.config.fallbackDelayMs * (2 ** (index - 1)));
      }
      try {
        const response = await this.fetchOnce(this.config.controlUrls[index], path, {
          method,
          token,
          body,
          requestId,
        });
        if (response.status === 429) {
          const retryAfterSeconds = parseRetryAfter(response.headers.get("Retry-After"));
          this.rateLimitedUntil = this.now() + retryAfterSeconds * 1000;
          await this.setRateLimitedUntil(this.rateLimitedUntil);
          throw await responseError(response, retryAfterSeconds);
        }
        if (RETRYABLE_STATUS.has(response.status) && index + 1 < this.config.controlUrls.length) {
          lastError = await responseError(response);
          continue;
        }
        if (!response.ok) {
          throw await responseError(response);
        }
        return await parseJson(response);
      } catch (error) {
        if (error instanceof ControlApiError) {
          if (error.status === 429 || !RETRYABLE_STATUS.has(error.status)) {
            throw error;
          }
          lastError = error;
        } else {
          lastError = new ControlApiError("Control API is unavailable");
        }
        if (index + 1 >= this.config.controlUrls.length) {
          break;
        }
      }
    }
    throw lastError ?? new ControlApiError("Control API is unavailable");
  }

  async fetchOnce(origin, path, {method, token, body, requestId}) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.requestTimeoutMs);
    const headers = {"X-Request-ID": requestId};
    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }
    let serializedBody;
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      serializedBody = JSON.stringify(body);
    }
    try {
      return await this.fetchImpl(`${origin}${path}`, {
        method,
        headers,
        body: serializedBody,
        cache: "no-store",
        credentials: "omit",
        redirect: "error",
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timeout);
    }
  }
}

async function parseJson(response) {
  try {
    return await response.json();
  } catch {
    throw new ControlApiError("Control API returned invalid JSON", {
      status: response.status,
      code: "INVALID_RESPONSE",
    });
  }
}

async function responseError(response, retryAfterSeconds = null) {
  let payload = null;
  try {
    payload = await response.json();
  } catch {
    // A malformed error body is still an HTTP error and must not expose its contents.
  }
  return new ControlApiError(payload?.error?.message || `HTTP ${response.status}`, {
    status: response.status,
    code: payload?.error?.code || "HTTP_ERROR",
    retryAfterSeconds,
  });
}

function parseRetryAfter(value) {
  if (value && /^\d+$/.test(value.trim())) {
    return Math.max(1, Math.min(3600, Number(value)));
  }
  return 60;
}
