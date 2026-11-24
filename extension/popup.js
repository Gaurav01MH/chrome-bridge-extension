const $ = id => document.getElementById(id);
let activeTab = null;
let currentOrigin = null;
let currentHasAccess = false;
let paired = false;

function setPill(element, state, label) {
  element.classList.remove("ok", "warn");
  if (state === "ok") element.classList.add("ok");
  if (state === "warn") element.classList.add("warn");
  element.querySelector("span:last-child").textContent = label;
}
function originLabel(pattern) {
  const separator = pattern.indexOf("://");
  if (separator < 0) return pattern;
  const host = pattern.slice(separator + 3);
  return host.endsWith("/*") ? host.slice(0, -2) : host;
}
function isOriginGranted(patterns, origin) {
  if (!origin) return false;
  try {
    const url = new URL(origin);
    return patterns.some(pattern => {
      if (pattern === "<all_urls>" || pattern === "*://*/*") return true;
      const separator = pattern.indexOf("://");
      if (separator < 0 || !pattern.endsWith("/*")) return false;
      const protocol = pattern.slice(0, separator);
      const hostPattern = pattern.slice(separator + 3, -2);
      const protocolMatches = protocol === "*" || protocol + ":" === url.protocol;
      const hostMatches = hostPattern === "*" || hostPattern === url.hostname ||
        (hostPattern.startsWith("*.") && (url.hostname === hostPattern.slice(2) || url.hostname.endsWith("." + hostPattern.slice(2))));
      return protocolMatches && hostMatches;
    });
  } catch { return false; }
}
function renderConnection(state) {
  const connected = !!state?.connected;
  const connecting = !!state?.connecting;
  if (connected) {
    setPill($("connectionPill"), "ok", "Connected");
    $("connectionHeadline").textContent = "Bridge is ready";
    $("connectionDetail").textContent = "Chrome is connected to your local ChromeBridge service.";
  } else if (connecting) {
    setPill($("connectionPill"), "warn", "Connecting");
    $("connectionHeadline").textContent = "Reconnecting to the local service";
    $("connectionDetail").textContent = "The extension is trying again automatically.";
  } else {
    setPill($("connectionPill"), "warn", "Offline");
    $("connectionHeadline").textContent = paired ? "Bridge is not connected" : "Pair ChromeBridge to get started";
    $("connectionDetail").textContent = paired
      ? "Start the local service. The extension will reconnect automatically."
      : "Save your pairing secret once, then the extension connects automatically.";
  }
}
async function refreshConnection() {
  try {
    const state = await chrome.runtime.sendMessage({ type: "chromeBridgeStatus" });
    renderConnection(state);
  } catch {
    renderConnection({ connected: false, connecting: false });
  }
}
function renderSites(origins) {
  const list = $("sitesList");
  list.replaceChildren();
  const unique = [...new Set(origins)].filter(x => x && x !== "<all_urls>");
  $("siteCount").textContent = unique.length + (unique.length === 1 ? " site" : " sites");
  if (unique.length) {
    for (const pattern of unique.slice(0, 6)) {
      const li = document.createElement("li");
      const host = document.createElement("span");
      host.className = "site-host";
      host.textContent = originLabel(pattern);
      const state = document.createElement("span");
      state.className = "site-state";
      state.textContent = "✓ Allowed";
      li.append(host, state);
      list.append(li);
    }
    if (unique.length > 6) {
      const li = document.createElement("li");
      li.className = "muted";
      li.textContent = "+" + (unique.length - 6) + " more connected sites";
      list.append(li);
    }
    list.hidden = false;
  } else {
    list.hidden = true;
  }
}
async function refreshSitePermissions() {
  try {
    const all = await chrome.permissions.getAll();
    const origins = all.origins || [];
    renderSites(origins);
    currentHasAccess = isOriginGranted(origins, currentOrigin);
    if (!currentOrigin) {
      $("currentSiteName").textContent = "No regular website selected";
      $("currentSiteHost").textContent = "Chrome internal page";
      $("currentSiteState").textContent = "Browser pages cannot be granted site access.";
      $("currentSiteBadge").querySelector("span:last-child").textContent = "Unavailable";
      $("siteAction").hidden = true;
    } else if (currentHasAccess) {
      $("currentSiteName").textContent = "Current tab";
      $("currentSiteHost").textContent = new URL(currentOrigin).hostname;
      $("currentSiteState").textContent = "Access is already granted for this site.";
      setPill($("currentSiteBadge"), "ok", "Allowed");
      $("siteAction").hidden = true;
    } else {
      $("currentSiteName").textContent = "Current tab";
      $("currentSiteHost").textContent = new URL(currentOrigin).hostname;
      $("currentSiteState").textContent = "This site has not been authorised yet.";
      setPill($("currentSiteBadge"), "warn", "Access needed");
      $("siteAction").textContent = "Allow access to " + new URL(currentOrigin).hostname;
      $("siteAction").hidden = false;
    }
  } catch {
    $("siteCount").textContent = "Unavailable";
    $("currentSiteState").textContent = "Could not read site permissions.";
  }
}
function renderDebugger(granted) {
  const button = $("debugger");
  button.disabled = false;
  button.textContent = "Recheck";
  if (granted) {
    setPill($("debuggerBadge"), "ok", "Enabled");
    $("debuggerLabel").textContent = "Mouse input is enabled";
    button.classList.add("success");
    $("debuggerHelp").textContent = "Chrome has approved the debugger permission. Supported controls can use mouse-level input.";
  } else {
    setPill($("debuggerBadge"), "warn", "Not approved");
    $("debuggerLabel").textContent = "Chrome permission is not active";
    button.classList.remove("success");
    $("debuggerHelp").textContent = "The debugger permission cannot be requested from this popup. Reload ChromeBridge on chrome://extensions and approve the additional permission when Chrome asks.";
  }
}
async function refreshDebugger() {
  try { renderDebugger(await chrome.permissions.contains({ permissions: ["debugger"] })); }
  catch {
    setPill($("debuggerBadge"), "warn", "Unknown");
    $("debuggerLabel").textContent = "Permission status unavailable";
    $("debugger").disabled = true;
  }
}
function renderPairing(hasSecret) {
  paired = hasSecret;
  $("pairingPanel").hidden = hasSecret;
  $("secretFields").hidden = hasSecret;
}
async function init() {
  try {
    const data = await chrome.storage.local.get(["pairingSecret"]);
    renderPairing(!!data.pairingSecret);
  } catch { renderPairing(false); }
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    activeTab = tab || null;
    if (tab?.url) { const parsed = new URL(tab.url); if (parsed.protocol === "http:" || parsed.protocol === "https:") currentOrigin = parsed.origin; }
  } catch {}
  await Promise.all([refreshConnection(), refreshSitePermissions(), refreshDebugger()]);
}
$("siteAction").addEventListener("click", () => {
  if (!currentOrigin || currentHasAccess) return;
  const hostPermission = currentOrigin + "/*";
  $("siteAction").disabled = true;
  $("siteAction").textContent = "Waiting for Chrome…";
  const request = chrome.permissions.request({ permissions: ["scripting"], origins: [hostPermission] });
  request.then(async granted => {
    $("siteAction").disabled = false;
    if (granted) {
      $("status").textContent = "Site access granted. It will now stay connected for this site.";
      await refreshSitePermissions();
    } else {
      $("status").textContent = "Site access was not granted.";
      $("siteAction").textContent = "Try again";
    }
  }).catch(() => {
    $("siteAction").disabled = false;
    $("siteAction").textContent = "Try again";
    $("status").textContent = "Could not request site access.";
  });
});
$("debugger").addEventListener("click", async () => {
  $("debugger").disabled = true;
  $("debugger").textContent = "Checking…";
  try {
    const granted = await chrome.permissions.contains({ permissions: ["debugger"] });
    renderDebugger(granted);
    $("status").textContent = granted
      ? "Verified: Chrome debugger permission is active."
      : "Not active yet. Reload the extension and approve Chrome's permission notice.";
  } catch {
    $("debugger").disabled = false;
    $("debugger").textContent = "Retry check";
    $("status").textContent = "Could not read Chrome's permission state.";
  }
});
$("save").addEventListener("click", async () => {
  const secret = $("secret").value.trim();
  if (!/^[a-f0-9]{64}$/i.test(secret)) {
    $("status").textContent = "Invalid secret: enter all 64 hexadecimal characters.";
    return;
  }
  try {
    await chrome.storage.local.set({ pairingSecret: secret });
    $("secret").value = "";
    renderPairing(true);
    $("status").textContent = "Pairing saved. Connecting to the local service…";
    await refreshConnection();
  } catch { $("status").textContent = "Could not save the pairing secret."; }
});
init();

[executed on device: LAPTOP-G72PTQJ6 (2b3fcac6-b6bc-499c-b844-33cea8460bff)]