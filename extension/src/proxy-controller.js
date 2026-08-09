export function createProxyController(proxySettings = chrome.proxy.settings) {
  return {
    async enable(proxy, bypassList) {
      validateProxy(proxy);
      const normalizedBypass = normalizeBypassList(bypassList);
      await proxySettings.set({
        scope: "regular",
        value: {
          mode: "fixed_servers",
          rules: {
            singleProxy: {
              scheme: "https",
              host: proxy.host,
              port: proxy.port,
            },
            bypassList: normalizedBypass,
          },
        },
      });
    },

    async disable() {
      await proxySettings.clear({scope: "regular"});
    },
  };
}

export function isCurrentProxyChallenge(details, currentProxy) {
  if (!details?.isProxy || !details.challenger || !currentProxy) {
    return false;
  }
  return normalizeHost(details.challenger.host) === normalizeHost(currentProxy.host)
    && Number(details.challenger.port) === Number(currentProxy.port);
}

export function proxyFromStatus(status) {
  if (!status?.vpn?.available || !status.vpn.node || !status.vpn.credentials) {
    return null;
  }
  return {
    nodeId: status.vpn.node.id,
    host: status.vpn.node.host,
    port: status.vpn.node.port,
    username: status.vpn.credentials.proxy_username,
    password: status.vpn.credentials.proxy_password,
    bypassList: status.vpn.bypass_list,
  };
}

function validateProxy(proxy) {
  if (
    !proxy
    || typeof proxy.host !== "string"
    || !proxy.host
    || !Number.isInteger(proxy.port)
    || proxy.port < 1
    || proxy.port > 65535
    || typeof proxy.username !== "string"
    || typeof proxy.password !== "string"
  ) {
    throw new Error("Invalid proxy configuration");
  }
}

function normalizeBypassList(values) {
  if (!Array.isArray(values) || values.length === 0) {
    throw new Error("Control API bypass list is required");
  }
  return [...new Set(values.map((value) => normalizeHost(value)).filter(Boolean))];
}

function normalizeHost(value) {
  return String(value || "").trim().toLowerCase().replace(/\.$/, "");
}
