import {BUILD_CONFIG} from "./src/config.js";
import {renderTelegramQr} from "./src/qr.js";

const screens = [...document.querySelectorAll("[data-screen]")];
const appShell = document.querySelector(".app-shell");
const notice = document.querySelector("#notice");
const iconNav = document.querySelector("#icon-nav");
const agreementLink = document.querySelector("#agreement-link");
let viewModel = null;
let currentScreen = "dashboard";
let pairingTimer = null;
let clockTimer = null;
let busy = false;
let availableNodes = null;
let paymentEmail = "";

document.addEventListener("click", (event) => {
  const actionElement = event.target.closest("[data-action]");
  if (!actionElement) return;
  event.preventDefault();
  void act(actionElement.dataset.action, actionElement);
});

agreementLink.addEventListener("click", (event) => {
  if (!BUILD_CONFIG.userAgreementUrl) {
    event.preventDefault();
    showNotice("Ссылка будет активирована перед публикацией соглашения.");
  }
});

void initialize();

async function initialize() {
  try {
    viewModel = await send("GET_VIEW");
    const preview = new URLSearchParams(location.search).get("preview");
    if (preview) {
      currentScreen = preview;
      if (preview === "locations") availableNodes = await send("GET_NODES");
    }
    render();
  } catch (error) {
    showNotice(error.message || "Не удалось запустить расширение.");
  }
}

async function act(action, actionElement = null) {
  if (busy) return;
  switch (action) {
    case "home":
    case "main":
      currentScreen = "dashboard";
      render();
      return;
    case "tariffs":
      currentScreen = "tariffs";
      render();
      void send("TRACK_EVENT", {eventType: "tariff_viewed"}).catch(() => undefined);
      return;
    case "settings":
      currentScreen = "settings";
      render();
      return;
    case "help":
      await openExternal(BUILD_CONFIG.telegramSupportUrl);
      return;
    case "locations":
      if (!viewModel.status?.access?.can_select_node) return;
      await runBusy(async () => {
        availableNodes = await send("GET_NODES");
        currentScreen = "locations";
        render();
      });
      return;
    case "select-node":
      await runBusy(async () => {
        viewModel = await send("SELECT_NODE", {nodeId: actionElement?.dataset.nodeId || null});
        availableNodes = null;
        currentScreen = "dashboard";
        render();
      });
      return;
    case "telegram":
      await openExternal(BUILD_CONFIG.telegramBotUrl);
      return;
    case "select-plan": {
      const selectedPlan = actionElement?.dataset.plan;
      if (!selectedPlan) return;
      for (const button of document.querySelectorAll(".plan-switch-button")) {
        const selected = button.dataset.plan === selectedPlan;
        button.classList.toggle("selected", selected);
        button.setAttribute("aria-selected", String(selected));
      }
      for (const panel of document.querySelectorAll("[data-tariff-panel]")) {
        panel.hidden = panel.dataset.tariffPanel !== selectedPlan;
      }
      document.querySelector("#plan-switch")?.classList.toggle("space-active", selectedPlan === "space");
      return;
    }
    case "select-period": {
      const card = actionElement?.closest(".tariff-panel");
      const plan = actionElement?.dataset.plan;
      const tariffCode = actionElement?.dataset.tariffCode;
      if (!card || !plan || !tariffCode) return;
      for (const option of card.querySelectorAll(".period-option")) {
        const selected = option === actionElement;
        option.classList.toggle("selected", selected);
        option.setAttribute("aria-checked", String(selected));
      }
      const paymentButton = card.querySelector(".plan-payment-button");
      const periodLabel = actionElement.querySelector("span")?.textContent || "";
      paymentButton.dataset.tariffCode = tariffCode;
      paymentButton.textContent = `Выбрать ${plan.toUpperCase()} · ${periodLabel}`;
      return;
    }
    case "create-payment": {
      const consentAccepted = Boolean(document.querySelector("#payment-consent")?.checked);
      const termsAccepted = consentAccepted;
      const recurringConsent = consentAccepted;
      if (!termsAccepted || !recurringConsent) {
        document.querySelector("#payment-consents")?.classList.add("attention");
        showNotice("Поставьте галочку согласия с политикой конфиденциальности внизу страницы. Пролистайте вниз.");
        return;
      }
      const email = await requestPaymentEmail();
      if (!email) return;
      await runBusy(async () => {
        const payment = await send("CREATE_PAYMENT", {
          tariffCode: actionElement?.dataset.tariffCode,
          email,
          termsAccepted,
          recurringConsent,
        });
        await openExternal(payment.payment_url);
      });
      return;
    }
    case "start-pairing":
    case "restart-pairing":
      await runBusy(async () => {
        viewModel = await send("START_PAIRING");
        render();
      });
      return;
    case "toggle-vpn":
      await runBusy(async () => {
        viewModel = await send("SET_VPN", {enabled: !viewModel.vpnEnabled});
        render();
      });
      return;
    case "logout":
      await runBusy(async () => {
        viewModel = await send("LOGOUT");
        currentScreen = "onboarding";
        render();
      });
      return;
    default:
  }
}

async function requestPaymentEmail() {
  const dialog = document.querySelector("#payment-email-dialog");
  const input = document.querySelector("#payment-email");
  input.value = paymentEmail;
  dialog.returnValue = "";
  dialog.showModal();
  input.focus();
  await new Promise((resolve) => dialog.addEventListener("close", resolve, {once: true}));
  if (dialog.returnValue !== "confirm") return null;
  paymentEmail = input.value.trim().toLowerCase();
  return paymentEmail;
}

async function runBusy(task) {
  busy = true;
  setButtonsDisabled(true);
  hideNotice();
  try {
    await task();
  } catch (error) {
    showNotice(error.message || "Операция не выполнена.");
  } finally {
    busy = false;
    setButtonsDisabled(false);
  }
}

function render() {
  clearTimeout(pairingTimer);
  clearInterval(clockTimer);
  iconNav.hidden = !viewModel.paired;
  agreementLink.href = BUILD_CONFIG.userAgreementUrl || "#";
  agreementLink.target = BUILD_CONFIG.userAgreementUrl ? "_blank" : "";
  agreementLink.rel = BUILD_CONFIG.userAgreementUrl ? "noreferrer" : "";
  agreementLink.setAttribute("aria-disabled", String(!BUILD_CONFIG.userAgreementUrl));

  let screen = currentScreen;
  if (!viewModel.paired) screen = viewModel.pairing ? "pairing" : "onboarding";
  if (viewModel.paired && !["dashboard", "tariffs", "locations", "settings"].includes(screen)) {
    screen = "dashboard";
  }
  appShell.classList.toggle("scrollable", screen === "locations");
  appShell.scrollTop = 0;
  for (const element of screens) element.hidden = element.dataset.screen !== screen;

  hideNotice();
  if (viewModel.lastError) showNotice(viewModel.lastError);
  if (screen === "pairing") renderPairing();
  if (screen === "dashboard") renderDashboard();
  if (screen === "locations") renderLocations();
  if (screen === "settings") {
    document.querySelector("#device-id").textContent = viewModel.status?.account_id || "—";
    document.querySelector("#account-state").textContent = viewModel.paired ? "Привязан" : "Не привязан";
  }
}

function renderPairing() {
  const pairing = viewModel.pairing;
  const link = document.querySelector("#telegram-link");
  link.href = pairing.telegramUrl;
  renderTelegramQr(document.querySelector("#telegram-qr"), pairing.telegramUrl);
  const remaining = Date.parse(pairing.expiresAt) - Date.now();
  if (remaining <= 0) {
    showNotice("Ссылка истекла. Создайте новую.");
    return;
  }
  pairingTimer = setTimeout(async () => {
    try {
      viewModel = await send("POLL_PAIRING");
      render();
    } catch (error) {
      showNotice(error.message || "Не удалось проверить вход.");
      pairingTimer = setTimeout(() => renderPairing(), Math.max(2, pairing.pollAfterSeconds) * 1000);
    }
  }, Math.max(2, pairing.pollAfterSeconds) * 1000);
}

function renderDashboard() {
  const status = viewModel.status;
  const connected = Boolean(viewModel.vpnEnabled && viewModel.proxyActive);
  const waiting = Boolean(viewModel.vpnEnabled && !viewModel.proxyActive);
  const power = document.querySelector("#power-button");
  power.classList.toggle("connected", connected);
  power.classList.toggle("waiting", waiting);
  power.setAttribute("aria-pressed", String(connected));
  document.querySelector("#power-label").textContent = connected
    ? "Отключиться"
    : waiting ? "Остановить" : "Подключиться";
  document.querySelector("#connection-dot").classList.toggle("connected", connected);
  const canSelectNode = Boolean(status?.access?.can_select_node);
  const serverLabelButton = document.querySelector("#server-label-button");
  const nodeButton = document.querySelector("#node-select-button");
  const node = status?.vpn?.node;
  document.querySelector("#node-name").textContent = canSelectNode
    ? node?.name || "Автоматически"
    : "Автоматически";
  document.querySelector("#node-flag").textContent = canSelectNode
    ? countryFlag(node?.country_code)
    : "";
  const serverAction = canSelectNode ? "locations" : "tariffs";
  const serverTitle = canSelectNode
    ? "Открыть выбор сервера"
    : "Выбор сервера доступен по подписке";
  for (const button of [serverLabelButton, nodeButton]) {
    button.dataset.action = serverAction;
    button.title = serverTitle;
    button.setAttribute("aria-label", serverTitle);
  }
  if (!viewModel.lastError && status?.vpn?.unavailable_reason) {
    const messages = {
      ACCESS_EXPIRED: "Доступ закончился. Продлите подписку.",
      USER_BLOCKED: "Доступ к аккаунту заблокирован.",
      NO_ACTIVE_NODE: "Ищем доступный VPN-сервер. Можно оставить ожидание включённым.",
    };
    showNotice(messages[status.vpn.unavailable_reason] || "VPN временно недоступен.");
  }

  const accessState = status?.access?.state;
  document.querySelector("#access-title").textContent = {
    trial: "Пробный период",
    paid: "Подписка активна",
    expired: "Доступ закончился",
    blocked: "Доступ заблокирован",
  }[accessState] || "Доступ Virgo";
  const expiry = status?.access?.access_expires_at;
  document.querySelector("#access-expiry").textContent = expiry
    ? `Активен до ${formatDate(expiry)}`
    : "Срок доступа ещё не получен";
  const renewalButton = document.querySelector("#renewal-button");
  const serverTime = Date.parse(status?.server_time || "");
  const expiryTime = Date.parse(expiry || "");
  const paidNotUrgent = accessState === "paid"
    && Number.isFinite(serverTime)
    && Number.isFinite(expiryTime)
    && expiryTime - serverTime > 3 * 86_400_000;
  renewalButton.classList.toggle("renewal-quiet", paidNotUrgent);
  updateConnectionClock();
  clockTimer = setInterval(updateConnectionClock, 1000);
}

function renderLocations() {
  const container = document.querySelector("#node-list");
  container.replaceChildren();
  const auto = document.createElement("button");
  auto.type = "button";
  auto.className = `node-choice ${availableNodes?.node_selection_mode === "auto" ? "selected" : ""}`;
  auto.dataset.action = "select-node";
  auto.innerHTML = "<span>Автоматически</span><small>Рекомендуем</small>";
  container.append(auto);
  for (const node of availableNodes?.nodes || []) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `node-choice ${node.selected ? "selected" : ""}`;
    button.dataset.action = "select-node";
    button.dataset.nodeId = node.id;
    const name = document.createElement("span");
    name.textContent = node.name;
    const country = document.createElement("small");
    country.textContent = node.country_code;
    button.append(name, country);
    container.append(button);
  }
}

function updateConnectionClock() {
  const target = document.querySelector("#connection-time");
  if (!viewModel.vpnEnabled || !viewModel.connectedAt) {
    target.textContent = "00:00";
    return;
  }
  const totalSeconds = Math.max(0, Math.floor((Date.now() - viewModel.connectedAt) / 1000));
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  target.textContent = hours > 0
    ? [hours, minutes, seconds].map(twoDigits).join(":")
    : [minutes, seconds].map(twoDigits).join(":");
}

function formatDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return new Intl.DateTimeFormat("ru-RU", {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

function twoDigits(value) {
  return String(value).padStart(2, "0");
}

function countryFlag(countryCode) {
  const code = String(countryCode || "").toUpperCase();
  if (!/^[A-Z]{2}$/.test(code)) return "";
  return [...code]
    .map((character) => String.fromCodePoint(127397 + character.charCodeAt(0)))
    .join("");
}

async function send(type, payload = {}) {
  if (!globalThis.chrome?.runtime?.sendMessage) {
    return previewResponse(type, payload);
  }
  const response = await chrome.runtime.sendMessage({type, ...payload});
  if (!response?.ok) throw new Error(response?.error || "Фоновый процесс не ответил.");
  return response.value;
}

function previewResponse(type, payload) {
  const preview = new URLSearchParams(location.search).get("preview") || "onboarding";
  if (type === "GET_VIEW") return previewModel(preview);
  if (type === "START_PAIRING") return previewModel("pairing");
  if (type === "POLL_PAIRING") return previewModel("main");
  if (type === "SET_VPN") {
    const model = previewModel("main");
    model.vpnEnabled = payload.enabled;
    model.connectedAt = payload.enabled ? Date.now() - 125_000 : null;
    return model;
  }
  if (type === "LOGOUT") return previewModel("onboarding");
  if (type === "GET_NODES") return {
    node_selection_mode: "manual",
    nodes: [
      {id: "00000000-0000-4000-8000-000000000001", name: "NL-1", country_code: "NL", selected: true},
      {id: "00000000-0000-4000-8000-000000000002", name: "DE-1", country_code: "DE", selected: false},
    ],
  };
  if (type === "CREATE_PAYMENT") return {
    payment_url: "https://app.lava.top/preview-payment",
  };
  return viewModel;
}

function previewModel(screen) {
  const paired = !["onboarding", "pairing"].includes(screen);
  return {
    paired,
    pairing: screen === "pairing" ? {
      telegramUrl: "https://t.me/example_vpn_bot?start=aKYkMPe8tIIRwWbBr72-lGz8teYWoJcC_38163orthM",
      expiresAt: new Date(Date.now() + 600_000).toISOString(),
      pollAfterSeconds: 60,
    } : null,
    vpnEnabled: screen === "main",
    proxyActive: screen === "main",
    connectedAt: screen === "main" ? Date.now() - 125_000 : null,
    status: paired ? {
      access: {
        state: screen === "locations" ? "paid" : "trial",
        access_expires_at: new Date(Date.now() + 86_400_000).toISOString(),
        can_select_node: screen === "locations",
      },
      vpn: {available: true, node: {name: "NL-1", country_code: "NL"}},
    } : null,
    lastError: null,
  };
}

async function openExternal(url) {
  if (!url) {
    showNotice("Ссылка на Telegram будет добавлена перед публикацией.");
    return;
  }
  const parsed = new URL(url);
  if (parsed.protocol !== "https:") throw new Error("Получена небезопасная ссылка.");
  if (globalThis.chrome?.tabs?.create) {
    await chrome.tabs.create({url: parsed.href});
    return;
  }
  window.location.assign(parsed.href);
}

function setButtonsDisabled(disabled) {
  for (const button of document.querySelectorAll("button")) button.disabled = disabled;
}

function showNotice(message) {
  notice.textContent = message;
  notice.hidden = false;
}

function hideNotice() {
  notice.hidden = true;
  notice.textContent = "";
}
