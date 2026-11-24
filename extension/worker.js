const PORT = 8765;
const CLICK_MARKER = "CHROMEBRIDGE_BUTTON_CLICKED";
const WS_ENDPOINT = `ws://127.0.0.1:${PORT}/bridge`;
let socket = null;
let connecting = false;
let bridgeAuthenticated = false;
let reconnectDelay = 1000;
let reconnectTimer = null;
let heartbeatTimer = null;

function scheduleReconnect() {
  if (reconnectTimer || connecting || socket?.readyState === WebSocket.OPEN) return;
  const delay = reconnectDelay;
  reconnectDelay = Math.min(reconnectDelay * 2, 30000);
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    connect();
  }, delay);
  chrome.alarms.create("chromeBridgeReconnect", {
    delayInMinutes: Math.max(0.5, delay / 60000)
  });
}

function hex(bytes) {
  return [...new Uint8Array(bytes)].map(b => b.toString(16).padStart(2, "0")).join("");
}
function fromHex(value) {
  return new Uint8Array((value.match(/.{2}/g) || []).map(x => parseInt(x, 16)));
}
async function hmac(secretHex, message) {
  const key = await crypto.subtle.importKey("raw", fromHex(secretHex), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return hex(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message)));
}
async function getSecret() {
  const stored = await chrome.storage.local.get(["pairingSecret"]);
  return stored.pairingSecret || null;
}
function send(value) {
  if (socket?.readyState === WebSocket.OPEN) socket.send(JSON.stringify(value));
}
async function connect() {
  if (connecting || socket?.readyState === WebSocket.CONNECTING || socket?.readyState === WebSocket.OPEN) return;
  connecting = true;
  let secret;
  try { secret = await getSecret(); }
  catch { connecting = false; scheduleReconnect(); return; }
  if (!secret) { connecting = false; return; }
  let ws;
  try { ws = new WebSocket(WS_ENDPOINT); }
  catch { connecting = false; scheduleReconnect(); return; }
  let handshake = null;
  let authenticated = false;
  socket = ws;
  ws.onmessage = async event => {
    let msg;
    try { msg = JSON.parse(event.data); } catch { ws.close(); return; }
    if (msg.type === "challenge") {
      const clientNonce = hex(crypto.getRandomValues(new Uint8Array(32)));
      const proof = await hmac(secret, `client|extension|${msg.nonce}|${clientNonce}`);
      ws.send(JSON.stringify({ type: "auth", role: "extension", clientNonce, proof }));
      handshake = { nonce: msg.nonce, clientNonce };
    } else if (msg.type === "authenticated") {
      if (!handshake) { ws.close(); return; }
      const expected = await hmac(secret, `server|extension|${handshake.nonce}|${handshake.clientNonce}`);
      if (msg.role !== "extension" || msg.proof !== expected) { ws.close(); return; }
      authenticated = true;
      bridgeAuthenticated = true;
      connecting = false;
      reconnectDelay = 1000;
      if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
      chrome.alarms.clear("chromeBridgeReconnect");
      ws.send(JSON.stringify({ type: "ready" }));
      chrome.storage.local.set({ connectedAt: Date.now() });
      if (heartbeatTimer) clearInterval(heartbeatTimer);
      heartbeatTimer = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: "heartbeat", at: Date.now() }));
        }
      }, 20000);
    } else if (msg.type === "pong") {
      return;
    } else if (msg.type === "command") {
      if (!authenticated) { ws.close(); return; }
      await handleCommand(msg);
    }
  };
  ws.onopen = () => {};
  ws.onclose = () => {
    bridgeAuthenticated = false;
    connecting = false;
    if (heartbeatTimer) { clearInterval(heartbeatTimer); heartbeatTimer = null; }
    if (socket === ws) socket = null;
    chrome.storage.local.set({ connectedAt: 0 });
    scheduleReconnect();
  };
  ws.onerror = () => {
    bridgeAuthenticated = false;
    connecting = false;
    try { ws.close(); } catch {}
  };
}

function waitForTabUrl(tabId, targetUrl, timeoutMs = 30000) {
  const target = new URL(targetUrl);
  const matches = url => {
    try {
      const actual = new URL(url);
      return actual.origin === target.origin &&
        actual.pathname.replace(/\/+$/, "") === target.pathname.replace(/\/+$/, "");
    } catch { return false; }
  };
  return new Promise((resolve, reject) => {
    let settled = false;
    let pollTimer = null;
    const cleanup = () => {
      clearTimeout(timer);
      if (pollTimer) clearInterval(pollTimer);
      chrome.tabs.onUpdated.removeListener(onUpdated);
      chrome.tabs.onRemoved.removeListener(onRemoved);
    };
    const finish = (error, tab) => {
      if (settled) return;
      settled = true;
      cleanup();
      if (error) reject(error);
      else resolve(tab);
    };
    const inspect = async () => {
      try {
        const tab = await chrome.tabs.get(tabId);
        if (matches(tab.url || "")) finish(null, tab);
      } catch (error) {
        finish(error);
      }
    };
    const onUpdated = (id, changeInfo, tab) => {
      if (id === tabId && (changeInfo.url || changeInfo.status === "complete") &&
          matches(tab.url || changeInfo.url || "")) {
        finish(null, tab);
      }
    };
    const onRemoved = id => {
      if (id === tabId) finish(new Error("TAB_CLOSED"));
    };
    const timer = setTimeout(() => finish(new Error("NAVIGATION_NOT_CONFIRMED")), timeoutMs);
    chrome.tabs.onUpdated.addListener(onUpdated);
    chrome.tabs.onRemoved.addListener(onRemoved);
    // Event-driven first; bounded tab-state polling catches SPA/history transitions
    // and navigation events that can be missed while the extension worker wakes.
    pollTimer = setInterval(inspect, 250);
    inspect();
  });
}
function isSafeClickTarget(item) {
  if (!item || item.disabled) return false;
  if (item.tag === "a") return !item.insideForm && /^https?:\/\//i.test(item.href);
  if (item.tag === "button" && item.buttonType === "button") return true;
  return item.tag !== "a" && !item.insideForm &&
    ["button", "tab", "menuitem"].includes(item.role);
}

async function handleCommand(msg) {
  if (!msg || typeof msg.id !== "string") return;
  let diagnosticStage = "command-start";
  try {
    if (msg.command === "reloadExtension") {
      send({ type: "result", id: msg.id, ok: true,
        data: { kind: "extension-reload", scheduled: true } });
      setTimeout(() => chrome.runtime.reload(), 1500);
      return;
    }
    if (msg.command === "listTabs") {
      const tabs = await chrome.tabs.query({});
      send({ type: "result", id: msg.id, ok: true, data: tabs.map(t => {
        let safeUrl = "";
        try { const u = new URL(t.url || ""); u.search = ""; u.hash = ""; safeUrl = u.href; } catch {}
        return { id: t.id, title: t.title || "", url: safeUrl, active: !!t.active, windowId: t.windowId };
      }) });
      return;
    }
    if (msg.command === "elements" && Number.isInteger(msg.tabId)) {
      const tab = await chrome.tabs.get(msg.tabId);
      if (!tab.url || !/^https?:\/\//i.test(tab.url)) throw new Error("PROTECTED_PAGE");
      const origin = new URL(tab.url).origin;
      if (!await chrome.permissions.contains({ origins: [origin + "/*"] })) throw new Error("SITE_PERMISSION_REQUIRED");
      const pageUrl = new URL(tab.url).origin + new URL(tab.url).pathname;
      const results = await chrome.scripting.executeScript({
        target: { tabId: msg.tabId },
        func: () => {
          const candidates = [...document.querySelectorAll(
            'a[href], button, [role="button"], [role="link"], [role="tab"], [role="menuitem"]'
          )];
          const visible = candidates.filter(el => {
            const style = getComputedStyle(el);
            const rect = el.getBoundingClientRect();
            return style.visibility !== "hidden" && style.display !== "none" &&
              Number(style.opacity) !== 0 && rect.width > 0 && rect.height > 0;
          }).slice(0, 120);
          return visible.map((el, index) => {
            const tag = el.tagName.toLowerCase();
            let href = "";
            if (tag === "a" && el.href) {
              try {
                const u = new URL(el.href);
                if (u.protocol === "http:" || u.protocol === "https:") {
                  u.search = ""; u.hash = ""; href = u.href.slice(0, 500);
                }
              } catch {}
            }
            return {
              index, tag, role: el.getAttribute("role") || "",
              text: (el.innerText || el.getAttribute("aria-label") || el.title || "")
                .replace(/\s+/g, " ").trim().slice(0, 140),
              href,
              buttonType: tag === "button" ? (el.getAttribute("type") || "submit").toLowerCase() : "",
              insideForm: !!el.closest("form"),
              disabled: !!el.disabled || el.getAttribute("aria-disabled") === "true",
              target: tag === "a" ? (el.getAttribute("target") || "") : ""
            };
          });
        }
      });
      const items = results?.[0]?.result || [];
      const scanId = crypto.randomUUID();
      await chrome.storage.session.set({ [`scan:${scanId}`]: {
        tabId: msg.tabId, pageUrl, createdAt: Date.now(), items
      } });
      send({ type: "result", id: msg.id, ok: true, data: { scanId, pageUrl, items } });
      return;
    }
    if (msg.command === "click" && Number.isInteger(msg.tabId) &&
        typeof msg.scanId === "string" && Number.isInteger(msg.index)) {
      const key = `scan:${msg.scanId}`;
      const saved = await chrome.storage.session.get(key);
      const scan = saved[key];
      if (!scan || scan.tabId !== msg.tabId || Date.now() - scan.createdAt > 60000) throw new Error("SCAN_EXPIRED");
      const expected = scan.items[msg.index];
      if (!expected || expected.index !== msg.index || !isSafeClickTarget(expected)) throw new Error("CLICK_TARGET_NOT_ALLOWED");
      const tab = await chrome.tabs.get(msg.tabId);
      if (!tab.url || new URL(tab.url).origin + new URL(tab.url).pathname !== scan.pageUrl) throw new Error("PAGE_CHANGED");
      const origin = new URL(tab.url).origin;
      if (!await chrome.permissions.contains({ origins: [origin + "/*"] })) throw new Error("SITE_PERMISSION_REQUIRED");
      if (expected.tag === "a") {
        if (!/^https?:\/\//i.test(expected.href) ||
            new URL(expected.href).origin !== origin ||
            (expected.target && expected.target !== "_self") ||
            expected.disabled || expected.insideForm) {
          throw new Error("CLICK_TARGET_NOT_ALLOWED");
        }
        const navigation = waitForTabUrl(msg.tabId, expected.href);
        const updated = await chrome.tabs.update(msg.tabId, { url: expected.href });
        if (!updated || updated.id !== msg.tabId) throw new Error("NAVIGATION_NOT_CONFIRMED");
        const verified = await navigation;
        await chrome.storage.session.remove(key);
        send({ type: "result", id: msg.id, ok: true,
          data: { kind: "navigation", confirmed: true, href: verified.url } });
        return;
      }
      if (!await chrome.permissions.contains({ permissions: ["debugger"] })) {
        throw new Error("DEBUGGER_PERMISSION_REQUIRED");
      }
      diagnosticStage = "geometry-executeScript";
      const geometryResults = await chrome.scripting.executeScript({
        target: { tabId: msg.tabId },
        args: [expected, scan.pageUrl],
        func: (expected, pageUrl) => {
          try {
          if (location.origin + location.pathname !== pageUrl) throw new Error("PAGE_CHANGED");
          const candidates = [...document.querySelectorAll(
            'a[href], button, [role="button"], [role="link"], [role="tab"], [role="menuitem"]'
          )];
          const visible = candidates.filter(el => {
            const style = getComputedStyle(el);
            const rect = el.getBoundingClientRect();
            return style.visibility !== "hidden" && style.display !== "none" &&
              Number(style.opacity) !== 0 && rect.width > 0 && rect.height > 0;
          }).slice(0, 120);
          const el = visible[expected.index];
          if (!el) throw new Error("TARGET_CHANGED");
          const tag = el.tagName.toLowerCase();
          const current = {
            index: expected.index, tag, role: el.getAttribute("role") || "",
            text: (el.innerText || el.getAttribute("aria-label") || el.title || "")
              .replace(/\s+/g, " ").trim().slice(0, 140),
            href: "",
            buttonType: tag === "button" ? (el.getAttribute("type") || "submit").toLowerCase() : "",
            insideForm: !!el.closest("form"),
            disabled: !!el.disabled || el.getAttribute("aria-disabled") === "true",
            target: ""
          };
          const mismatches = Object.keys(current).filter(key => current[key] !== expected[key]);
            if (mismatches.length) throw new Error(`TARGET_CHANGED:${mismatches.join(",")}`);
          const nativeButton = tag === "button" && current.buttonType === "button";
          const ariaAction = tag !== "a" && !current.insideForm &&
            ["button", "tab", "menuitem"].includes(current.role);
          if ((!nativeButton && !ariaAction) || current.disabled) {
            throw new Error("CLICK_TARGET_NOT_ALLOWED");
          }
          el.scrollIntoView({ block: "center", inline: "center" });
          const rect = el.getBoundingClientRect();
          if (rect.width <= 0 || rect.height <= 0) throw new Error("TARGET_NOT_VISIBLE");
          const x = rect.left + rect.width / 2;
          const y = rect.top + rect.height / 2;
          if (x < 0 || y < 0 || x >= window.innerWidth || y >= window.innerHeight) {
            throw new Error("CLICK_COORDINATES_OUTSIDE_VIEWPORT");
          }
          const hit = document.elementFromPoint(x, y);
          if (!hit || (hit !== el && !el.contains(hit))) {
            throw new Error("CLICK_COORDINATES_OBSCURED");
          }
          return { ok: true, x, y,
            beforeText: (document.body?.innerText || "").slice(0, 10000),
            beforeExpanded: el.getAttribute("aria-expanded"),
            beforePressed: el.getAttribute("aria-pressed"),
            beforeSelected: el.getAttribute("aria-selected") };
          } catch (error) {
            return { ok: false, diagnosticError: String(error?.message || error).slice(0, 180) };
          }
        }
      });
      diagnosticStage = "geometry-result-check";
      const geometrySummary = Array.isArray(geometryResults)
        ? geometryResults.map(entry => ({
            frameId: entry?.frameId ?? null,
            documentIdPresent: typeof entry?.documentId === "string",
            resultType: typeof entry?.result,
            resultKeys: entry?.result && typeof entry.result === "object"
              ? Object.keys(entry.result).slice(0, 12) : [],
            hasError: !!entry?.error,
            error: entry?.error ? String(entry.error).slice(0, 180) : null
          }))
        : null;
      const point = geometryResults?.[0]?.result;
      if (!point || point.ok === false ||
          !Number.isFinite(point.x) || !Number.isFinite(point.y)) {
        const detail = point?.diagnosticError
          ? `INJECTED_FUNCTION_ERROR:${point.diagnosticError}`
          : geometrySummary?.[0]?.error
            ? "INJECTED_FUNCTION_ERROR"
            : !Array.isArray(geometryResults) || geometryResults.length === 0
              ? "NO_INJECTION_RESULT"
              : !point
                ? "RESULT_MISSING"
                : point.ok === false
                  ? "INJECTED_FUNCTION_ERROR"
                  : "NON_FINITE_COORDINATES";
        throw new Error(`CLICK_COORDINATES_UNAVAILABLE:${detail}:${JSON.stringify(geometrySummary)}`);
      }
      diagnosticStage = "debugger-attach-and-input";
      const debugTarget = { tabId: msg.tabId };
      let attached = false;
      try {
        await chrome.debugger.attach(debugTarget, "1.3");
        attached = true;
        await chrome.debugger.sendCommand(debugTarget, "Input.dispatchMouseEvent", {
          type: "mouseMoved", x: point.x, y: point.y, button: "none"
        });
        await chrome.debugger.sendCommand(debugTarget, "Input.dispatchMouseEvent", {
          type: "mousePressed", x: point.x, y: point.y, button: "left", clickCount: 1
        });
        await chrome.debugger.sendCommand(debugTarget, "Input.dispatchMouseEvent", {
          type: "mouseReleased", x: point.x, y: point.y, button: "left", clickCount: 1
        });
      } finally {
        if (attached) {
          try { await chrome.debugger.detach(debugTarget); } catch {}
        }
      }
      diagnosticStage = "post-click-verification";
      await new Promise(resolve => setTimeout(resolve, 250));
      const afterResults = await chrome.scripting.executeScript({
        target: { tabId: msg.tabId },
        func: () => ({ url: location.origin + location.pathname,
          text: (document.body?.innerText || "").slice(0, 10000) })
      });
      const after = afterResults?.[0]?.result;
      const tabAfter = await chrome.tabs.get(msg.tabId);
      const effectObserved = !!after && (
        after.text !== point.beforeText ||
        after.url !== scan.pageUrl ||
        tabAfter.url !== tab.url
      );
      await chrome.storage.session.remove(key);
      send({ type: "result", id: msg.id, ok: true,
        data: { kind: "button", inputDispatched: true, effectObserved,
          verification: effectObserved ? "page-state-changed" : "input-sent-effect-not-observed" } });
      return;
    }
    if (msg.command === "textTargets" && Number.isInteger(msg.tabId)) {
      const tab = await chrome.tabs.get(msg.tabId);
      if (!tab.url || !/^https?:\/\//i.test(tab.url)) throw new Error("PROTECTED_PAGE");
      const origin = new URL(tab.url).origin;
      if (!await chrome.permissions.contains({ origins: [origin + "/*"] })) throw new Error("SITE_PERMISSION_REQUIRED");
      const pageUrl = new URL(tab.url).origin + new URL(tab.url).pathname;
      const results = await chrome.scripting.executeScript({
        target: { tabId: msg.tabId },
        func: () => {
          const candidates = [...document.querySelectorAll(
            'textarea, input:not([type]), input[type="text"], input[type="search"], [contenteditable="true"], [role="textbox"]'
          )];
          const visible = candidates.filter(el => {
            const style = getComputedStyle(el);
            const rect = el.getBoundingClientRect();
            return style.visibility !== "hidden" && style.display !== "none" &&
              Number(style.opacity) !== 0 && rect.width > 0 && rect.height > 0 &&
              !el.disabled && !el.readOnly && el.getAttribute("aria-disabled") !== "true";
          }).slice(0, 40);
          return visible.map((el, index) => ({
            index, tag: el.tagName.toLowerCase(),
            role: el.getAttribute("role") || "",
            ariaLabel: el.getAttribute("aria-label") || "",
            placeholder: el.getAttribute("placeholder") || el.getAttribute("data-placeholder") || "",
            inputType: el.tagName.toLowerCase() === "input" ? (el.type || "text") : "",
            contentEditable: el.isContentEditable,
            disabled: !!el.disabled, readOnly: !!el.readOnly
          }));
        }
      });
      const items = results?.[0]?.result || [];
      const scanId = crypto.randomUUID();
      await chrome.storage.session.set({ [`textscan:${scanId}`]: {
        tabId: msg.tabId, pageUrl, createdAt: Date.now(), items
      } });
      send({ type: "result", id: msg.id, ok: true, data: { scanId, pageUrl, items } });
      return;
    }
    if (msg.command === "typeText" && Number.isInteger(msg.tabId) &&
        typeof msg.scanId === "string" && Number.isInteger(msg.index) &&
        typeof msg.text === "string" && msg.text.length > 0 && msg.text.length <= 1500 &&
        !/\u0000/.test(msg.text)) {
      const key = `textscan:${msg.scanId}`;
      const saved = await chrome.storage.session.get(key);
      const scan = saved[key];
      if (!scan || scan.tabId !== msg.tabId || Date.now() - scan.createdAt > 60000) throw new Error("TEXT_SCAN_EXPIRED");
      const expected = scan.items[msg.index];
      if (!expected || expected.index !== msg.index || expected.disabled || expected.readOnly) throw new Error("TEXT_TARGET_NOT_ALLOWED");
      const tab = await chrome.tabs.get(msg.tabId);
      if (!tab.url || new URL(tab.url).origin + new URL(tab.url).pathname !== scan.pageUrl) throw new Error("PAGE_CHANGED");
      const origin = new URL(tab.url).origin;
      if (!await chrome.permissions.contains({ origins: [origin + "/*"] })) throw new Error("SITE_PERMISSION_REQUIRED");
      if (!await chrome.permissions.contains({ permissions: ["debugger"] })) throw new Error("DEBUGGER_PERMISSION_REQUIRED");
      const geometry = await chrome.scripting.executeScript({
        target: { tabId: msg.tabId }, args: [expected, scan.pageUrl],
        func: (expected, pageUrl) => {
          try {
            if (location.origin + location.pathname !== pageUrl) throw new Error("PAGE_CHANGED");
            const candidates = [...document.querySelectorAll(
              'textarea, input:not([type]), input[type="text"], input[type="search"], [contenteditable="true"], [role="textbox"]'
            )];
            const visible = candidates.filter(el => {
              const style = getComputedStyle(el); const rect = el.getBoundingClientRect();
              return style.visibility !== "hidden" && style.display !== "none" &&
                Number(style.opacity) !== 0 && rect.width > 0 && rect.height > 0 &&
                !el.disabled && !el.readOnly && el.getAttribute("aria-disabled") !== "true";
            }).slice(0, 40);
            const el = visible[expected.index];
            if (!el) throw new Error("TEXT_TARGET_CHANGED");
            const current = {
              index: expected.index, tag: el.tagName.toLowerCase(),
              role: el.getAttribute("role") || "",
              ariaLabel: el.getAttribute("aria-label") || "",
              placeholder: el.getAttribute("placeholder") || el.getAttribute("data-placeholder") || "",
              inputType: el.tagName.toLowerCase() === "input" ? (el.type || "text") : "",
              contentEditable: el.isContentEditable,
              disabled: !!el.disabled, readOnly: !!el.readOnly
            };
            if (Object.keys(current).some(k => current[k] !== expected[k])) throw new Error("TEXT_TARGET_CHANGED");
            if (["password", "file", "hidden"].includes(current.inputType)) throw new Error("TEXT_TARGET_NOT_ALLOWED");
            const rect = el.getBoundingClientRect();
            const x = rect.left + rect.width / 2; const y = rect.top + rect.height / 2;
            if (x < 0 || y < 0 || x >= innerWidth || y >= innerHeight) throw new Error("TEXT_TARGET_OUTSIDE_VIEWPORT");
            const hit = document.elementFromPoint(x, y);
            if (!hit || (hit !== el && !el.contains(hit))) throw new Error("TEXT_TARGET_OBSCURED");
            return { ok: true, x, y };
          } catch (e) { return { ok: false, error: String(e?.message || e).slice(0, 140) }; }
        }
      });
      const point = geometry?.[0]?.result;
      if (!point?.ok) throw new Error(`TEXT_TARGET_GEOMETRY_FAILED:${point?.error || "NO_RESULT"}`);
      const target = { tabId: msg.tabId };
      let attached = false;
      try {
        await chrome.debugger.attach(target, "1.3"); attached = true;
        await chrome.debugger.sendCommand(target, "Input.dispatchMouseEvent", {
          type: "mouseMoved", x: point.x, y: point.y, button: "none"
        });
        await chrome.debugger.sendCommand(target, "Input.dispatchMouseEvent", {
          type: "mousePressed", x: point.x, y: point.y, button: "left", clickCount: 1
        });
        await chrome.debugger.sendCommand(target, "Input.dispatchMouseEvent", {
          type: "mouseReleased", x: point.x, y: point.y, button: "left", clickCount: 1
        });
        await chrome.debugger.sendCommand(target, "Input.insertText", { text: msg.text });
      } finally {
        if (attached) { try { await chrome.debugger.detach(target); } catch {} }
      }
      await chrome.storage.session.remove(key);
      send({ type: "result", id: msg.id, ok: true, data: {
        kind: "text-entry", inputDispatched: true, characters: msg.text.length, submitted: false
      } });
      return;
    }
    if (msg.command === "submitGeminiPrompt" && Number.isInteger(msg.tabId)) {
      const tab = await chrome.tabs.get(msg.tabId);
      const url = new URL(tab.url || "");
      if (url.hostname !== "gemini.google.com" || url.pathname !== "/app") {
        throw new Error("GEMINI_SUBMIT_ONLY");
      }
      if (!await chrome.permissions.contains({ origins: ["https://gemini.google.com/*"] }) ||
          !await chrome.permissions.contains({ permissions: ["debugger"] })) {
        throw new Error("GEMINI_PERMISSION_REQUIRED");
      }
      const check = await chrome.scripting.executeScript({
        target: { tabId: msg.tabId },
        func: () => {
          const editor = document.activeElement;
          const editable = !!editor && (editor.isContentEditable ||
            editor.getAttribute("role") === "textbox" || editor.tagName === "TEXTAREA");
          const label = editor?.getAttribute("aria-label") || "";
          const content = (editor?.innerText || editor?.value || "").trim();
          const button = document.querySelector('button[aria-label="Send message"]');
          if (!editable || label !== "Enter a prompt for Gemini" || !content) {
            return { ok: false, error: "GEMINI_COMPOSER_NOT_READY" };
          }
          if (!button || button.disabled || button.getAttribute("aria-disabled") === "true") {
            return { ok: false, error: "GEMINI_SEND_BUTTON_UNAVAILABLE" };
          }
          const style = getComputedStyle(button); const rect = button.getBoundingClientRect();
          if (style.visibility === "hidden" || style.display === "none" ||
              rect.width <= 0 || rect.height <= 0) return { ok: false, error: "GEMINI_SEND_BUTTON_NOT_VISIBLE" };
          const x = rect.left + rect.width / 2; const y = rect.top + rect.height / 2;
          const hit = document.elementFromPoint(x, y);
          if (!hit || (hit !== button && !button.contains(hit))) return { ok: false, error: "GEMINI_SEND_BUTTON_OBSCURED" };
          return { ok: true, x, y, promptLength: content.length };
        }
      });
      const point = check?.[0]?.result;
      if (!point?.ok) throw new Error(point?.error || "GEMINI_COMPOSER_CHECK_FAILED");
      const target = { tabId: msg.tabId }; let attached = false;
      try {
        await chrome.debugger.attach(target, "1.3"); attached = true;
        await chrome.debugger.sendCommand(target, "Input.dispatchMouseEvent", {
          type: "mouseMoved", x: point.x, y: point.y, button: "none"
        });
        await chrome.debugger.sendCommand(target, "Input.dispatchMouseEvent", {
          type: "mousePressed", x: point.x, y: point.y, button: "left", clickCount: 1
        });
        await chrome.debugger.sendCommand(target, "Input.dispatchMouseEvent", {
          type: "mouseReleased", x: point.x, y: point.y, button: "left", clickCount: 1
        });
      } finally {
        if (attached) { try { await chrome.debugger.detach(target); } catch {} }
      }
      send({ type: "result", id: msg.id, ok: true, data: {
        kind: "gemini-submit", inputDispatched: true, promptLength: point.promptLength
      } });
      return;
    }
    if (msg.command === "probeGeometry" && Number.isInteger(msg.tabId) &&
        typeof msg.scanId === "string" && Number.isInteger(msg.index)) {
      const key = `scan:${msg.scanId}`;
      const saved = await chrome.storage.session.get(key);
      const scan = saved[key];
      if (!scan || scan.tabId !== msg.tabId || Date.now() - scan.createdAt > 60000) {
        throw new Error("SCAN_EXPIRED");
      }
      const expected = scan.items[msg.index];
      if (!expected || expected.index !== msg.index || !isSafeClickTarget(expected)) {
        throw new Error("CLICK_TARGET_NOT_ALLOWED");
      }
      const tab = await chrome.tabs.get(msg.tabId);
      if (!tab.url || new URL(tab.url).origin + new URL(tab.url).pathname !== scan.pageUrl) {
        throw new Error("PAGE_CHANGED");
      }
      const origin = new URL(tab.url).origin;
      if (!await chrome.permissions.contains({ origins: [origin + "/*"] })) {
        throw new Error("SITE_PERMISSION_REQUIRED");
      }
      const results = await chrome.scripting.executeScript({
        target: { tabId: msg.tabId },
        args: [expected, scan.pageUrl],
        func: (expected, pageUrl) => {
          try {
            if (location.origin + location.pathname !== pageUrl) throw new Error("PAGE_CHANGED");
            const candidates = [...document.querySelectorAll(
              'a[href], button, [role="button"], [role="link"], [role="tab"], [role="menuitem"]'
            )];
            const visible = candidates.filter(el => {
              const style = getComputedStyle(el);
              const rect = el.getBoundingClientRect();
              return style.visibility !== "hidden" && style.display !== "none" &&
                Number(style.opacity) !== 0 && rect.width > 0 && rect.height > 0;
            }).slice(0, 120);
            const el = visible[expected.index];
            if (!el) throw new Error("TARGET_CHANGED");
            const tag = el.tagName.toLowerCase();
            const current = {
              index: expected.index, tag, role: el.getAttribute("role") || "",
              text: (el.innerText || el.getAttribute("aria-label") || el.title || "")
                .replace(/\s+/g, " ").trim().slice(0, 140),
              href: "",
              buttonType: tag === "button" ? (el.getAttribute("type") || "submit").toLowerCase() : "",
              insideForm: !!el.closest("form"),
              disabled: !!el.disabled || el.getAttribute("aria-disabled") === "true",
              target: ""
            };
            const mismatches = Object.keys(current).filter(key => current[key] !== expected[key]);
            if (mismatches.length) throw new Error(`TARGET_CHANGED:${mismatches.join(",")}`);
            const nativeButton = tag === "button" && current.buttonType === "button";
            const ariaAction = tag !== "a" && !current.insideForm &&
              ["button", "tab", "menuitem"].includes(current.role);
            if ((!nativeButton && !ariaAction) || current.disabled) {
              throw new Error("CLICK_TARGET_NOT_ALLOWED");
            }
            el.scrollIntoView({ block: "center", inline: "center" });
            const rect = el.getBoundingClientRect();
            const x = rect.left + rect.width / 2;
            const y = rect.top + rect.height / 2;
            const hit = document.elementFromPoint(x, y);
            return {
              ok: true, x, y, width: rect.width, height: rect.height,
              viewportWidth: window.innerWidth, viewportHeight: window.innerHeight,
              devicePixelRatio: window.devicePixelRatio,
              hitTestMatches: !!hit && (hit === el || el.contains(hit)),
              hitTag: hit?.tagName?.toLowerCase() || null,
              hitRole: hit?.getAttribute?.("role") || null
            };
          } catch (error) {
            return { ok: false, diagnosticError: String(error?.message || error).slice(0, 180) };
          }
        }
      });
      const result = results?.[0]?.result;
      if (!result || result.ok !== true) {
        throw new Error(`GEOMETRY_PROBE_FAILED:${result?.diagnosticError || "RESULT_MISSING"}`);
      }
      send({ type: "result", id: msg.id, ok: true, data: result });
      return;
    }
    if (msg.command === "formInfo" && Number.isInteger(msg.tabId)) {
      const tab = await chrome.tabs.get(msg.tabId);
      if (!tab.url || new URL(tab.url).hostname !== "github.com" ||
          new URL(tab.url).pathname !== "/new") throw new Error("REPOSITORY_FORM_ONLY");
      if (!await chrome.permissions.contains({ origins: ["https://github.com/*"] })) {
        throw new Error("SITE_PERMISSION_REQUIRED");
      }
      const results = await chrome.scripting.executeScript({
        target: { tabId: msg.tabId },
        func: () => {
          const forms = [...document.forms].filter(form => {
            const action = new URL(form.action || location.href, location.href);
            return action.origin === location.origin &&
              (action.pathname.includes("/repositories") || location.pathname === "/new");
          });
          return forms.slice(0, 3).map(form => ({
            action: new URL(form.action || location.href, location.href).pathname,
            method: (form.method || "get").toLowerCase(),
            fields: [...form.querySelectorAll("input,select,textarea,button")].slice(0, 40).map(el => ({
              tag: el.tagName.toLowerCase(),
              type: (el.getAttribute("type") || "").toLowerCase(),
              role: (el.getAttribute("role") || "").slice(0, 40),
              ariaChecked: el.getAttribute("aria-checked"),
              label: (el.parentElement?.innerText || el.innerText || "").replace(/\s+/g, " ").trim().slice(0, 100),
              name: (el.getAttribute("name") || "").slice(0, 100),
              id: (el.id || "").slice(0, 100),
              placeholder: (el.getAttribute("placeholder") || "").slice(0, 100),
              required: !!el.required,
              disabled: !!el.disabled,
              checked: "checked" in el ? !!el.checked : null,
              text: el.tagName === "BUTTON" ? (el.innerText || "").trim().slice(0, 80) : ""
            }))
          }));
        }
      });
      const info = results?.[0]?.result;
      if (!Array.isArray(info)) throw new Error("FORM_INSPECTION_UNCONFIRMED");
      send({ type: "result", id: msg.id, ok: true, data: info });
      return;
    }
    if (msg.command === "createRepository" && Number.isInteger(msg.tabId)) {
      if (typeof msg.repoName !== "string" ||
          !/^[a-z0-9](?:[a-z0-9.-]{0,98}[a-z0-9])?$/i.test(msg.repoName) ||
          msg.repoName.includes("..") ||
          typeof msg.description !== "string" ||
          msg.description.trim().length < 1 || msg.description.length > 160 ||
          /[\u0000-\u001f\u007f]/.test(msg.description)) {
        throw new Error("INVALID_REPOSITORY_DETAILS");
      }
      const repoName = msg.repoName;
      const description = msg.description.trim();
      const tab = await chrome.tabs.get(msg.tabId);
      if (!tab.url || new URL(tab.url).hostname !== "github.com" ||
          new URL(tab.url).pathname !== "/new") throw new Error("REPOSITORY_FORM_ONLY");
      if (!await chrome.permissions.contains({ origins: ["https://github.com/*"] })) {
        throw new Error("SITE_PERMISSION_REQUIRED");
      }
      const repositoryUrl = `https://github.com/Gaurav01MH/${repoName}`;
      const navigation = waitForTabUrl(msg.tabId, repositoryUrl, 45000);
      const results = await chrome.scripting.executeScript({
        target: { tabId: msg.tabId },
        args: [repoName, description],
        func: (repoName, description) => {
          if (location.origin !== "https://github.com" || location.pathname !== "/new") {
            throw new Error("REPOSITORY_FORM_ONLY");
          }
          const owner = document.querySelector("#owner-dropdown-header-button");
          const name = document.querySelector("#repository-name-input");
          const descriptionField = document.querySelector('input[name="Description"]');
          const visibility = document.querySelector("#visibility-anchor-button");
          const submit = [...document.querySelectorAll("button[type='submit']")]
            .find(button => (button.innerText || "").trim() === "Create repository");
          if (!owner || (owner.innerText || "").trim() !== "Gaurav01MH") throw new Error("OWNER_MISMATCH");
          if (!name || !descriptionField || !visibility ||
              (visibility.innerText || "").trim() !== "Public" ||
              !submit || submit.disabled) throw new Error("REPOSITORY_FORM_NOT_READY");
          const form = name.closest("form");
          if (!form || !form.contains(submit) || !form.contains(descriptionField)) {
            throw new Error("REPOSITORY_FORM_MISMATCH");
          }
          const readmeToggle = form.querySelector('button[aria-labelledby="add-readme"]');
          if (!readmeToggle) throw new Error("README_TOGGLE_NOT_FOUND");
          const readmeEnabled = () => readmeToggle.getAttribute("aria-pressed") === "true" &&
            readmeToggle.getAttribute("data-checked") === "true";
          if (!readmeEnabled()) readmeToggle.click();
          const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
          setter.call(name, repoName);
          name.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertText", data: repoName }));
          name.dispatchEvent(new Event("change", { bubbles: true }));
          setter.call(descriptionField, description);
          descriptionField.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertText", data: description }));
          descriptionField.dispatchEvent(new Event("change", { bubbles: true }));
          if (name.value !== repoName || descriptionField.value !== description) {
            throw new Error("REPOSITORY_DETAILS_FILL_UNCONFIRMED");
          }
          if ((visibility.innerText || "").trim() !== "Public") throw new Error("VISIBILITY_MISMATCH");
          setTimeout(() => {
            if (location.origin === "https://github.com" && location.pathname === "/new" &&
                name.value === repoName && descriptionField.value === description &&
                (visibility.innerText || "").trim() === "Public" &&
                (owner.innerText || "").trim() === "Gaurav01MH" &&
                readmeEnabled() && form.checkValidity()) {
              form.requestSubmit(submit);
            }
          }, 250);
          return "CHROMEBRIDGE_REPOSITORY_SUBMIT_SCHEDULED";
        }
      });
      const first = Array.isArray(results) ? results[0] : undefined;
      if (first?.error) throw new Error("REPOSITORY_SUBMIT_SCRIPT_FAILED");
      if (first?.result !== "CHROMEBRIDGE_REPOSITORY_SUBMIT_SCHEDULED") {
        throw new Error("REPOSITORY_SUBMIT_NOT_SCHEDULED");
      }
      const verified = await navigation;
      if (!verified?.url) throw new Error("REPOSITORY_CREATION_UNCONFIRMED");
      const finalUrl = new URL(verified.url);
      if (finalUrl.origin !== "https://github.com" ||
          finalUrl.pathname.toLowerCase() !== `/gaurav01mh/${repoName.toLowerCase()}`) {
        throw new Error("REPOSITORY_CREATION_UNCONFIRMED");
      }
      send({ type: "result", id: msg.id, ok: true,
        data: { kind: "repository", created: true, owner: "Gaurav01MH",
          name: repoName, description, visibility: "public", url: finalUrl.href } });
      return;
    }
    if (msg.command === "snapshot" && Number.isInteger(msg.tabId)) {
      const tab = await chrome.tabs.get(msg.tabId);
      if (!tab.url || !/^https?:\/\//i.test(tab.url)) throw new Error("PROTECTED_PAGE");
      const origin = new URL(tab.url).origin;
      if (!await chrome.permissions.contains({ origins: [origin + "/*"] })) throw new Error("SITE_PERMISSION_REQUIRED");
      const results = await chrome.scripting.executeScript({
        target: { tabId: msg.tabId },
        func: () => ({ title: document.title, url: location.origin + location.pathname,
          text: (document.body?.innerText || "").slice(0, 12000) })
      });
      send({ type: "result", id: msg.id, ok: true, data: results?.[0]?.result || null });
      return;
    }
    throw new Error("COMMAND_NOT_ALLOWED");
  } catch (error) {
    const message = String(error?.message || "ACTION_FAILED").slice(0, 360);
    send({ type: "result", id: msg.id, ok: false,
      error: `${diagnosticStage}:${message}` });
  }
}
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "chromeBridgeStatus") {
    sendResponse({
      connected: bridgeAuthenticated && socket?.readyState === WebSocket.OPEN,
      connecting: connecting || socket?.readyState === WebSocket.CONNECTING
    });
  }
});
chrome.runtime.onStartup.addListener(connect);
chrome.runtime.onInstalled.addListener(connect);
chrome.alarms.onAlarm.addListener(alarm => {
  if (alarm.name === "chromeBridgeReconnect") connect();
});
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.pairingSecret) connect();
});
connect();

[executed on device: LAPTOP-G72PTQJ6 (2b3fcac6-b6bc-499c-b844-33cea8460bff)]