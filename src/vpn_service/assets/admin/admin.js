const formatBytes = (value) => {
  const bytes = Number(value || 0);
  if (bytes < 1024) return `${bytes} Б`;
  const units = ["КБ", "МБ", "ГБ", "ТБ"];
  let current = bytes / 1024;
  let index = 0;
  while (current >= 1024 && index < units.length - 1) { current /= 1024; index += 1; }
  return `${current.toFixed(current >= 10 ? 1 : 2)} ${units[index]}`;
};
const formatDuration = (seconds) => {
  const value = Number(seconds || 0);
  if (value < 60) return `${value} сек`;
  if (value < 3600) return `${Math.round(value / 60)} мин`;
  return `${(value / 3600).toFixed(1)} ч`;
};
const time = (value) => value ? new Date(value).toLocaleString("ru-RU") : "—";

async function api(path, options = {}) {
  const response = await fetch(`/admin/api/${path}`, {
    cache: "no-store",
    ...options,
    headers: {
      ...(options.body ? {"Content-Type": "application/json", "X-Admin-Action": "1"} : {}),
      ...(options.headers || {}),
    },
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.detail || `Ошибка HTTP ${response.status}`);
  return body;
}

function cell(row, textValue, className = "") {
  const element = document.createElement("td");
  element.textContent = textValue;
  if (className) element.className = className;
  row.append(element);
  return element;
}

function showNotice(message, error = false) {
  const notice = document.querySelector("#notice");
  notice.textContent = message;
  notice.className = `notice${error ? " error" : ""}`;
  notice.hidden = false;
  window.setTimeout(() => { notice.hidden = true; }, 12000);
}

async function renderOverview() {
  const data = await api("overview");
  const definitions = [
    ["Первых запусков", data.extension_installations], ["Всего запусков", data.extension_launches],
    ["Регистраций", data.registrations], ["Бесплатный период", data.free_active],
    ["Платная подписка", data.paid_active], ["Платёжных ссылок", data.payment_links_created],
    ["Активных VPN-сеансов", data.active_vpn_sessions], ["Ошибок за 24 часа", data.connection_errors_24h],
    ["Активных нод", data.active_nodes], ["Заблокированных нод", data.blocked_nodes],
    ["Входящий трафик", formatBytes(data.traffic_input_bytes)], ["Исходящий трафик", formatBytes(data.traffic_output_bytes)],
  ];
  const root = document.querySelector("#overview"); root.replaceChildren();
  for (const [label, value] of definitions) {
    const card = document.createElement("div"); card.className = "card";
    const title = document.createElement("span"); title.textContent = label;
    const number = document.createElement("strong"); number.textContent = String(value);
    card.append(title, number); root.append(card);
  }
  document.querySelector("#download-note").textContent = data.download_count_note;
}

async function nodeAction(nodeId, action, capacityUsers = null, tokenId = null) {
  const body = {
    action,
    ...(capacityUsers ? {capacity_users: Number(capacityUsers)} : {}),
    ...(tokenId ? {token_id: tokenId} : {}),
  };
  const result = await api(`nodes/${nodeId}/actions`, {method: "POST", body: JSON.stringify(body)});
  showNotice(result.node_credentials_token
    ? `ТОКЕН ПОКАЗЫВАЕТСЯ ОДИН РАЗ:\nID: ${result.token_id}\n${result.node_credentials_token}`
    : `Действие выполнено: ${action}`);
  await refreshAll();
}

function actionButton(container, label, action, node, className = "") {
  const button = document.createElement("button"); button.type = "button"; button.textContent = label; button.className = className;
  button.addEventListener("click", async () => {
    if (!window.confirm(`${label}: ${node.name}?`)) return;
    try {
      const capacity = action === "set_capacity" ? window.prompt("Новая вместимость", node.capacity_users) : null;
      if (action === "set_capacity" && !capacity) return;
      const tokenId = ["promote_token", "revoke_token"].includes(action)
        ? window.prompt("ID токена") : null;
      if (["promote_token", "revoke_token"].includes(action) && !tokenId) return;
      await nodeAction(node.id, action, capacity, tokenId);
    } catch (error) { showNotice(error.message, true); }
  });
  container.append(button);
}

async function renderNodes() {
  const data = await api("nodes");
  const body = document.querySelector("#nodes"); body.replaceChildren();
  for (const node of data.nodes) {
    const row = document.createElement("tr");
    cell(row, `${node.country_code} ${node.name}\n${node.host}:${node.port}`);
    const status = cell(row, ""); const badge = document.createElement("span"); badge.className = `status ${node.status}`; badge.textContent = node.status; status.append(badge);
    cell(row, `${node.assigned_users}/${node.capacity_users}\nсвободно ${node.free_capacity}`);
    cell(row, `sync: ${time(node.last_sync_at)}\nACK ошибок: ${node.snapshot_ack_failures}\ncanary: ${node.quality_outcome || "—"} / ${node.quality_latency_ms ?? "—"} мс`);
    const runtime = node.runtime;
    cell(row, runtime ? `CPU ${runtime.cpu_percent}%\nRAM ${runtime.memory_percent}%\nДиск ${runtime.disk_percent}%\nGOST ${runtime.gost_up ? "OK" : "DOWN"}` : "Нет телеметрии");
    cell(row, `${formatBytes(node.input_bytes)} ↓\n${formatBytes(node.output_bytes)} ↑\n${node.current_connections} сейчас`);
    const actions = cell(row, "", "actions");
    actionButton(actions, "Токен", "issue_current_token", node);
    actionButton(actions, "Next-токен", "issue_next_token", node);
    actionButton(actions, "Сделать next основным", "promote_token", node);
    actionButton(actions, "Отозвать токен", "revoke_token", node, "danger");
    actionButton(actions, "Активировать", "activate", node, "good");
    actionButton(actions, "Capacity", "set_capacity", node);
    actionButton(actions, "Drain", "drain_prepare", node);
    actionButton(actions, "Завершить drain", "drain_finalize", node);
    actionButton(actions, "Заблокировать", "block", node, "danger");
    actionButton(actions, "Восстановить", "recover", node, "good");
    if (node.tokens.length) {
      const tokens = document.createElement("small");
      tokens.className = "token-list mono";
      tokens.textContent = node.tokens
        .map((token) => `${token.status}: ${token.id}${token.expires_at ? ` до ${time(token.expires_at)}` : ""}`)
        .join("\n");
      actions.append(tokens);
    }
    body.append(row);
  }
  document.querySelector("#nodes-updated").textContent = time(data.generated_at);
}

async function renderUsers() {
  const data = await api("users?limit=300");
  const body = document.querySelector("#users"); body.replaceChildren();
  for (const user of data.users) {
    const row = document.createElement("tr");
    cell(row, String(user.telegram_id), "mono");
    const access = cell(row, ""); const badge = document.createElement("span"); badge.className = `status ${user.access}`; badge.textContent = user.access; access.append(badge);
    cell(row, `${user.last_ip || "—"}\n${time(user.last_seen_at)}\nустройств: ${user.devices}`);
    cell(row, `${user.assigned_node_id || "—"}\n${user.node_selection_mode}`, "mono");
    cell(row, `${formatBytes(user.input_bytes)} ↓\n${formatBytes(user.output_bytes)} ↑`);
    cell(row, `${user.current_connections} сейчас\n${user.total_connections} всего\nошибок ${user.traffic_errors}`);
    cell(row, `${user.vpn_sessions} сеансов\n${formatDuration(user.vpn_duration_seconds)}\nтуннель-время ${formatDuration(user.connection_seconds)}`);
    body.append(row);
  }
  document.querySelector("#users-updated").textContent = time(data.generated_at);
}

async function renderEvents() {
  const data = await api("events?limit=100");
  const body = document.querySelector("#events"); body.replaceChildren();
  for (const event of data.events) {
    const row = document.createElement("tr");
    cell(row, time(event.received_at)); cell(row, event.user_id, "mono");
    cell(row, event.event_type); cell(row, event.error_code || "—"); cell(row, event.source_ip);
    body.append(row);
  }
}

async function refreshAll() {
  try { await Promise.all([renderOverview(), renderNodes(), renderUsers(), renderEvents()]); }
  catch (error) { showNotice(error.message, true); }
}

document.querySelector("#refresh").addEventListener("click", refreshAll);
document.querySelector("#add-node").addEventListener("submit", async (event) => {
  event.preventDefault(); const values = Object.fromEntries(new FormData(event.currentTarget));
  values.capacity_users = Number(values.capacity_users); values.port = 443;
  try { await api("nodes", {method:"POST", body:JSON.stringify(values)}); event.currentTarget.reset(); showNotice("Нода добавлена в warming"); await refreshAll(); }
  catch (error) { showNotice(error.message, true); }
});
document.querySelector("#add-canary").addEventListener("submit", async (event) => {
  event.preventDefault(); const values = Object.fromEntries(new FormData(event.currentTarget));
  try { const result = await api("canaries", {method:"POST", body:JSON.stringify(values)}); showNotice(`ТОКЕН КАНАРЕЙКИ ПОКАЗЫВАЕТСЯ ОДИН РАЗ:\nID: ${result.canary_id}\n${result.canary_token}`); event.currentTarget.reset(); }
  catch (error) { showNotice(error.message, true); }
});
void refreshAll();
