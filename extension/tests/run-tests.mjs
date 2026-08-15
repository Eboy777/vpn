import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
import {ControlApiClient, ControlApiError} from "../src/api-client.js";
import {controlHostnames, validateBuildConfig} from "../src/config.js";
import {verifyDiscoveryDocument} from "../src/discovery.js";
import {
  createProxyController,
  isCurrentProxyChallenge,
  proxyFromStatus,
} from "../src/proxy-controller.js";
import {encodeTelegramQr} from "../src/qr.js";
import {shouldDisableProxy} from "../src/safety.js";
import {initialState, publicView} from "../src/storage.js";
import {initializePairingWithRecovery} from "../src/pairing-recovery.js";

const tests = [];
const test = (name, implementation) => tests.push([name, implementation]);
const config = {
  controlUrls: ["https://api-a.vpn.test", "https://api-b.vpn.test"],
  requestTimeoutMs: 1_000,
  fallbackDelayMs: 1,
  statusAlarmMinutes: 1,
  controlOfflineGraceSeconds: 300,
  userAgreementUrl: "",
  telegramBotUrl: "https://t.me/example_vpn_bot",
  telegramSupportUrl: "https://t.me/example_vpn_bot?start=support",
};

test("build config requires two distinct HTTPS origins", () => {
  assert.deepEqual(controlHostnames(config), ["api-a.vpn.test", "api-b.vpn.test"]);
  assert.throws(() => validateBuildConfig({...config, controlUrls: ["https://one.test"]}));
  assert.throws(() => validateBuildConfig({
    ...config,
    controlUrls: ["https://same.test", "https://same.test"],
  }));
  assert.throws(() => validateBuildConfig({
    ...config,
    controlUrls: ["https://one.test/path", "https://two.test"],
  }));
  assert.throws(() => validateBuildConfig({...config, controlOfflineGraceSeconds: 59}));
  assert.throws(() => validateBuildConfig({...config, userAgreementUrl: "http://legal.test"}));
  assert.throws(() => validateBuildConfig({
    ...config,
    controlUrls: ["https://same.test", "https://same.test:443"],
  }));
});

test("network error falls back once and keeps the request ID", async () => {
  const calls = [];
  const client = new ControlApiClient({
    config,
    randomUUID: () => "request-id",
    sleep: async () => undefined,
    fetchImpl: async (url, options) => {
      calls.push({url, options});
      if (calls.length === 1) throw new TypeError("network down");
      return new Response(JSON.stringify({status: "ok"}), {
        status: 200,
        headers: {"Content-Type": "application/json"},
      });
    },
  });

  assert.equal((await client.status("d".repeat(43))).status, "ok");
  assert.equal(calls.length, 2);
  assert.equal(calls[0].options.headers["X-Request-ID"], "request-id");
  assert.equal(calls[1].options.headers["X-Request-ID"], "request-id");
  assert.equal(calls[0].options.headers.Authorization, `Bearer ${"d".repeat(43)}`);
  assert.equal(calls[0].options.headers["Content-Type"], undefined);
});

test("signed discovery updates control addresses without an extension update", async () => {
  const keys = await crypto.subtle.generateKey(
    {name: "ECDSA", namedCurve: "P-256"},
    true,
    ["sign", "verify"],
  );
  const publicKey = encodeBase64Url(
    new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey)),
  );
  const now = Date.now();
  const document = {
    control_urls: ["https://new-a.vpn.test", "https://new-b.vpn.test"],
    expires_at: new Date(now + 3_600_000).toISOString(),
    generated_at: new Date(now).toISOString(),
    key_id: "test",
    version: "a".repeat(64),
  };
  document.signature = encodeBase64Url(new Uint8Array(await crypto.subtle.sign(
    {name: "ECDSA", hash: "SHA-256"},
    keys.privateKey,
    new TextEncoder().encode(JSON.stringify(document)),
  )));
  const verified = await verifyDiscoveryDocument(document, {test: publicKey}, {now});
  const client = new ControlApiClient({
    config,
    fetchImpl: async () => new Response("{}"),
  });
  client.setControlUrls(verified.control_urls);

  assert.deepEqual(client.controlHostnames(), ["new-a.vpn.test", "new-b.vpn.test"]);
});

test("429 is global and is never bypassed through fallback", async () => {
  let calls = 0;
  let now = 1_000;
  let persistedUntil = 0;
  const client = new ControlApiClient({
    config,
    now: () => now,
    getRateLimitedUntil: async () => persistedUntil,
    setRateLimitedUntil: async (value) => { persistedUntil = value; },
    sleep: async () => undefined,
    fetchImpl: async () => {
      calls += 1;
      return new Response(JSON.stringify({error: {code: "RATE_LIMITED", message: "slow"}}), {
        status: 429,
        headers: {"Content-Type": "application/json", "Retry-After": "12"},
      });
    },
  });

  await assert.rejects(() => client.status("d".repeat(43)), (error) => {
    assert(error instanceof ControlApiError);
    assert.equal(error.code, "RATE_LIMITED");
    assert.equal(error.retryAfterSeconds, 12);
    return true;
  });
  await assert.rejects(() => client.status("d".repeat(43)), {code: "RATE_LIMITED"});
  assert.equal(calls, 1);
  assert.equal(persistedUntil, 13_000);
  const restartedClient = new ControlApiClient({
    config,
    now: () => now,
    getRateLimitedUntil: async () => persistedUntil,
    fetchImpl: async () => { calls += 1; },
  });
  await assert.rejects(() => restartedClient.status("d".repeat(43)), {code: "RATE_LIMITED"});
  assert.equal(calls, 1);
  now += 12_001;
});

test("ordinary 4xx response does not use fallback", async () => {
  let calls = 0;
  const client = new ControlApiClient({
    config,
    sleep: async () => undefined,
    fetchImpl: async () => {
      calls += 1;
      return new Response(JSON.stringify({error: {code: "INVALID_DEVICE_TOKEN"}}), {
        status: 401,
        headers: {"Content-Type": "application/json"},
      });
    },
  });
  await assert.rejects(() => client.status("x".repeat(43)), {code: "INVALID_DEVICE_TOKEN"});
  assert.equal(calls, 1);
});

test("stale paired device identity is rotated before a new Telegram pairing", async () => {
  const firstState = initialState("00000000-0000-4000-8000-000000000001");
  const secondState = initialState("00000000-0000-4000-8000-000000000002");
  const calls = [];
  let resetCalls = 0;
  const store = {
    read: async () => firstState,
    reset: async () => {
      resetCalls += 1;
      return secondState;
    },
  };
  const api = {
    pairingInit: async (deviceId) => {
      calls.push(deviceId);
      if (calls.length === 1) {
        throw new ControlApiError("already paired", {
          status: 409,
          code: "DEVICE_ALREADY_PAIRED",
        });
      }
      return {pairing_session_token: "new-session"};
    },
  };

  const initialized = await initializePairingWithRecovery(api, store);

  assert.equal(resetCalls, 1);
  assert.deepEqual(calls, [firstState.deviceId, secondState.deviceId]);
  assert.equal(initialized.state.deviceId, secondState.deviceId);
  assert.equal(initialized.result.pairing_session_token, "new-session");
});

test("proxy uses HTTPS singleProxy and preserves the API bypass list", async () => {
  const calls = [];
  const controller = createProxyController({
    set: async (value) => calls.push(["set", value]),
    clear: async (value) => calls.push(["clear", value]),
  });
  const proxy = {
    host: "nl-1.proxy.test",
    port: 443,
    username: "user",
    password: "password",
  };
  await controller.enable(proxy, ["api-a.vpn.test", "api-b.vpn.test"]);
  await controller.disable();

  assert.equal(calls[0][1].value.mode, "fixed_servers");
  assert.deepEqual(calls[0][1].value.rules.singleProxy, {
    scheme: "https",
    host: "nl-1.proxy.test",
    port: 443,
  });
  assert.deepEqual(calls[0][1].value.rules.bypassList, [
    "api-a.vpn.test",
    "api-b.vpn.test",
  ]);
  assert.deepEqual(calls[1], ["clear", {scope: "regular"}]);
});

test("credentials are returned only for the exact current proxy challenge", () => {
  const proxy = {host: "nl-1.proxy.test", port: 443};
  assert.equal(isCurrentProxyChallenge({
    isProxy: true,
    challenger: {host: "NL-1.PROXY.TEST.", port: 443},
  }, proxy), true);
  assert.equal(isCurrentProxyChallenge({
    isProxy: false,
    challenger: {host: "nl-1.proxy.test", port: 443},
  }, proxy), false);
  assert.equal(isCurrentProxyChallenge({
    isProxy: true,
    challenger: {host: "other.proxy.test", port: 443},
  }, proxy), false);
  assert.equal(isCurrentProxyChallenge({
    isProxy: true,
    challenger: {host: "nl-1.proxy.test", port: 8443},
  }, proxy), false);
});

test("popup view receives account ID but never proxy credentials or device ID", () => {
  const state = initialState("00000000-0000-4000-8000-000000000001");
  state.deviceToken = "secret-device-token";
  state.vpnEnabled = true;
  state.currentProxy = {host: "proxy.test", port: 443, username: "u", password: "p"};
  state.status = {
    account_id: 123456789,
    vpn: {credentials: {proxy_username: "u", proxy_password: "p"}},
  };
  const view = publicView(state);
  assert.equal(view.proxyActive, true);
  assert.equal("deviceId" in view, false);
  assert.equal(view.status.account_id, 123456789);
  assert.equal("deviceToken" in view, false);
  assert.equal("credentials" in view.status.vpn, false);
});

test("popup exposes legal consent state without exposing its timestamp", () => {
  const state = initialState("00000000-0000-4000-8000-000000000001");
  assert.equal(publicView(state).legalConsentAccepted, false);
  state.legalConsentVersion = "2026-08-15";
  state.legalConsentAcceptedAt = "2026-08-15T00:00:00.000Z";
  const view = publicView(state);
  assert.equal(view.legalConsentAccepted, true);
  assert.equal("legalConsentAcceptedAt" in view, false);
});

test("status conversion requires node and credentials together", () => {
  assert.equal(proxyFromStatus({vpn: {available: false}}), null);
  assert.deepEqual(proxyFromStatus({
    vpn: {
      available: true,
      node: {id: "node", host: "proxy.test", port: 443},
      credentials: {proxy_username: "u", proxy_password: "p"},
      bypass_list: ["api-a.vpn.test", "api-b.vpn.test"],
    },
  }), {
    nodeId: "node",
    host: "proxy.test",
    port: 443,
    username: "u",
    password: "p",
    bypassList: ["api-a.vpn.test", "api-b.vpn.test"],
  });
});

test("offline safety stops at the earliest grace or access deadline", () => {
  const base = Date.parse("2026-08-09T00:00:00Z");
  assert.equal(shouldDisableProxy({
    now: base + 299_999,
    accessExpiresAt: "2026-08-10T00:00:00Z",
    controlUnavailableSince: base,
    controlOfflineGraceSeconds: 300,
  }), false);
  assert.equal(shouldDisableProxy({
    now: base + 300_000,
    accessExpiresAt: "2026-08-10T00:00:00Z",
    controlUnavailableSince: base,
    controlOfflineGraceSeconds: 300,
  }), true);
  assert.equal(shouldDisableProxy({
    now: base + 55_000,
    accessExpiresAt: "2026-08-09T00:01:00Z",
    controlUnavailableSince: base,
    controlOfflineGraceSeconds: 300,
  }), true);
  assert.equal(shouldDisableProxy({
    now: base + 54_999,
    accessExpiresAt: "2026-08-09T00:01:00Z",
    controlUnavailableSince: null,
    controlOfflineGraceSeconds: 300,
  }), false);
});

test("bundled QR encoder produces a Version 5 matrix", () => {
  const url = "https://t.me/example_vpn_bot?start=" + "a".repeat(43);
  const matrix = encodeTelegramQr(url);
  assert.equal(matrix.length, 37);
  assert(matrix.every((row) => row.length === 37));
  assert.equal(matrix[0][0], true);
  assert.equal(matrix[3][3], true);
  assert.equal(matrix[3][33], true);
  assert.equal(matrix[33][3], true);
  assert.equal(matrix[29][8], true);
  assert.throws(() => encodeTelegramQr("x".repeat(107)));
});

test("popup follows the approved copy and privacy changes", async () => {
  const html = await readFile(new URL("../popup.html", import.meta.url), "utf8");
  const css = await readFile(new URL("../popup.css", import.meta.url), "utf8");
  const script = await readFile(new URL("../popup.js", import.meta.url), "utf8");
  const configScript = await readFile(new URL("../src/config.js", import.meta.url), "utf8");
  assert.equal(html.includes("Unblock your digital world"), false);
  assert.equal(html.includes("Device ID"), false);
  assert.equal(html.includes("<dt>Тема</dt>"), false);
  assert.equal(html.includes('<dt>ID</dt><dd id="device-id">'), true);
  assert.equal(html.includes("Пользовательское соглашение"), true);
  assert.equal(html.includes('id="pairing-consent"'), true);
  assert.equal(html.includes('id="qr-consent-hint"'), false);
  assert.equal(html.includes('class="qr-consent-hint"'), true);
  assert.equal(html.includes("/legal/personal-data-consent"), true);
  assert.equal(html.includes('id="telegram-link" href="#" aria-disabled="true"'), true);
  assert.equal(html.includes("Выбрать сервер:"), true);
  assert.equal(html.includes("Virgo FLOW"), true);
  assert.equal(html.includes("Virgo SPACE"), true);
  assert.equal(html.includes("299 ₽"), true);
  assert.equal(html.includes("1 499 ₽"), true);
  assert.equal(html.includes("Тестовый тариф Lava"), false);
  assert.equal(html.includes("vpn_30d"), false);
  assert.equal(html.includes('data-tariff-code="flow_3m"'), true);
  assert.equal(html.includes('data-tariff-code="space_6m"'), true);
  assert.equal(html.includes('src="assets/virgo-logo.png"'), true);
  assert.equal(html.includes("v1.0.0"), false);
  assert.equal(html.includes("brand-version"), false);
  assert.equal(css.includes("border: 1px solid rgba(255,255,255,.38)"), true);
  assert.equal(css.includes("border-radius: 0"), true);
  assert.equal(css.includes(".app-shell.scrollable"), true);
  assert.equal(css.includes("justify-content: flex-end"), true);
  assert.equal(
    script.includes('appShell.classList.toggle("scrollable", screen === "locations")'),
    true,
  );
  assert.equal(script.includes('const serverAction = canSelectNode ? "locations" : "tariffs"'), true);
  assert.equal(script.includes("countryFlag(node?.country_code)"), true);
  assert.equal(script.includes("BUILD_CONFIG.telegramBotUrl"), true);
  assert.equal(script.includes("BUILD_CONFIG.telegramSupportUrl"), true);
  assert.equal(script.includes("chrome.tabs.create({url: parsed.href})"), true);
  assert.equal(script.includes("Поставьте галочку согласия с политикой конфиденциальности"), true);
  assert.equal(script.includes('send("ACCEPT_LEGAL", {version: "2026-08-15"})'), true);
  assert.equal(script.includes('send("START_PAIRING")'), true);
  assert.equal(html.includes('class="consent-row"'), true);
  assert.equal(html.includes('id="payment-consent"'), true);
  assert.equal(html.includes('id="payment-email-dialog"'), true);
  assert.equal(html.includes('id="payment-email"'), true);
  assert.equal(script.includes("const email = await requestPaymentEmail()"), true);
  assert.equal(html.includes('id="payment-terms"'), false);
  assert.equal(html.includes('id="payment-recurring"'), false);
  assert.equal(html.includes('class="plan-notification"'), true);
  assert.equal(html.includes("Увеличенный лимит скорости"), true);
  assert.equal(html.includes('class="round-icon telegram-icon"'), true);
  assert.equal(script.includes('case "select-plan"'), true);
  assert.equal(script.includes('case "select-period"'), true);
  assert.equal(configScript.includes("?start=support"), true);
  assert.equal(configScript.includes("https://proxy1.virgo-vpn.site"), true);
  assert.equal(configScript.includes("https://proxy2.virgo-vpn.site"), true);
  assert.equal(configScript.includes("https://api.virgo-vpn.site"), false);
  assert.equal(html.includes("https://api.virgo-vpn.site"), false);
  assert.equal(css.includes(".renewal-button.renewal-quiet"), true);
});

test("manifest has only the required MV3 permissions and local popup code", async () => {
  const manifest = JSON.parse(await readFile(new URL("../manifest.json", import.meta.url), "utf8"));
  assert.equal(manifest.manifest_version, 3);
  assert.deepEqual([...manifest.permissions].sort(), [
    "alarms",
    "proxy",
    "storage",
    "webRequest",
    "webRequestAuthProvider",
  ]);
  assert.deepEqual(manifest.host_permissions, ["<all_urls>"]);
  assert.equal(manifest.background.type, "module");
  assert.equal(manifest.action.default_popup, "popup.html");
  assert.deepEqual(Object.keys(manifest.icons), ["16", "32", "48", "128"]);
  for (const [size, path] of Object.entries(manifest.icons)) {
    const png = await readFile(new URL(`../${path}`, import.meta.url));
    assert.equal(png.subarray(1, 4).toString("ascii"), "PNG");
    assert.equal(png.readUInt32BE(16), Number(size));
    assert.equal(png.readUInt32BE(20), Number(size));
  }
  const insideLogo = await readFile(new URL("../assets/virgo-logo.png", import.meta.url));
  assert.equal(insideLogo.subarray(1, 4).toString("ascii"), "PNG");
  assert.equal(insideLogo.readUInt32BE(16), 178);
  assert.equal(insideLogo.readUInt32BE(20), 256);
  assert.equal("content_security_policy" in manifest, false);
});

function encodeBase64Url(value) {
  return Buffer.from(value).toString("base64url");
}

const failures = [];
for (const [name, implementation] of tests) {
  try {
    await implementation();
    console.log(`ok - ${name}`);
  } catch (error) {
    failures.push(`${name}: ${error?.stack || error}`);
    console.error(`not ok - ${name}`);
    console.error(error);
  }
}
if (failures.length > 0) throw new Error(failures.join("\n\n"));
console.log(`passed ${tests.length} extension tests`);
