import {BUILD_CONFIG} from "./src/config.js";
import {renderTelegramQr} from "./src/qr.js";

const screens = [...document.querySelectorAll("[data-screen]")];
const notice = document.querySelector("#notice");
const version = document.querySelector("#version");
const iconNav = document.querySelector("#icon-nav");
const agreementLink = document.querySelector("#agreement-link");
let viewModel = null;
let currentScreen = "dashboard";
let pairingTimer = null;
let clockTimer = null;
let busy = false;
let availableNodes = null;

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
      return;
    case "settings":
    case "help":
      currentScreen = "settings";
      render();
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
      openExternal(BUILD_CONFIG.supportUrl);
      return;
    case "payment-placeholder":
      showNotice("Оплата пока отключена до завершения юридической и фискальной настройки.");
      return;
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
  version.textContent = `v${viewModel.extensionVersion}`;
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
  for (const element of screens) element.hidden = element.dataset.screen !== screen;

  hideNotice();
  if (viewModel.lastError) showNotice(viewModel.lastError);
  if (screen === "pairing") renderPairing();
  if (screen === "dashboard") renderDashboard();
  if (screen === "locations") renderLocations();
  if (screen === "settings") {
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
  document.querySelector("#node-name").textContent = status?.vpn?.node?.name || "—";
  document.querySelector("#node-select-button").disabled = !status?.access?.can_select_node;
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
    extensionVersion: "1.0.0",
  };
}

function openExternal(url) {
  if (!url) {
    showNotice("Ссылка поддержки будет добавлена перед публикацией.");
    return;
  }
  window.open(url, "_blank", "noopener,noreferrer");
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
