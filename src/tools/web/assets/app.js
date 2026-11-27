(function () {
  "use strict";

  const MAX_PACKETS = 60;
  const state = {
    connected: false,
    authRequired: false,
    authenticated: false,
    paused: false,
    filter: "",
    packets: [],
    sse: null
  };

  const $ = (id) => document.getElementById(id);

  function showToast(msg) {
    const el = $("toast");
    el.textContent = msg;
    el.classList.remove("hidden");
    clearTimeout(showToast.timer);
    showToast.timer = setTimeout(() => el.classList.add("hidden"), 2800);
  }

  async function apiFetch(url, opts) {
    const res = await fetch(url, opts || {});
    const text = await res.text();
    let data = {};
    try { data = text ? JSON.parse(text) : {}; } catch (_) {}
    if (res.status === 401) {
      if (url === "/api/login") {
        throw new Error(data.error === "invalid passcode"
          ? "Wrong passcode. Check the host terminal and try again."
          : (data.error || "Invalid passcode"));
      }
      showLogin(true);
      throw new Error("Authentication required");
    }
    if (!res.ok) {
      throw new Error(data.error || ("Request failed (" + res.status + ")"));
    }
    return data;
  }

  function showLogin(show) {
    $("login-view").classList.toggle("hidden", !show);
    if (show) {
      closeSse();
      $("passcode-input").focus();
    }
  }

  function formatNum(v) {
    return Number(v || 0).toLocaleString();
  }

  function updateCounters(c) {
    const src = c || {};
    $("cnt-total").textContent = formatNum(src.total);
    $("cnt-desynced").textContent = formatNum(src.desynced);
    $("cnt-modified").textContent = formatNum(src.modified);
    $("cnt-passed").textContent = formatNum(src.passed);
  }

  function setDotClass(dot, mode) {
    dot.className = "signal-dot signal-dot-" + mode;
  }

  function applyStatusSnapshot(snap) {
    state.connected = Boolean(snap && snap.connected);
    const d = snap && snap.daemon ? snap.daemon : null;

    $("reload-lists-btn").disabled = !state.connected;
    $("stop-ask-btn").disabled = !state.connected;
    if (!state.connected) {
      hideStopConfirm();
    }

    if (state.connected && d) {
      setDotClass($("conn-dot"), d.intercept ? "ok" : "warn");
      $("conn-label").textContent = d.intercept ? "Connected" : "Dry mode";
      $("version-chip").textContent = "v" + d.version;
      $("engine-state").textContent = d.intercept ? "Intercepting traffic" : "Pass-through mode";
      $("engine-meta").textContent =
        "pid " + d.pid + "  qnum " + d.qnum + "  fwmark 0x" + Number(d.fwmark).toString(16);
      updateCounters(d.counters);

      const chips = $("profiles-row");
      chips.replaceChildren();
      (d.profile_names || []).forEach((name) => {
        const span = document.createElement("span");
        span.className = "chip mono";
        span.textContent = name;
        chips.appendChild(span);
      });
    } else {
      setDotClass($("conn-dot"), snap && snap.error ? "err" : "idle");
      $("conn-label").textContent = "Standby";
      $("version-chip").textContent = "--";
      $("engine-state").textContent = "Daemon offline";
      $("engine-meta").textContent =
        (snap && snap.error) || "Start nfqws2 daemon on host to inspect live packets";
      $("profiles-row").replaceChildren();
      updateCounters(null);
    }

    if (snap && Array.isArray(snap.recent_packets) && state.packets.length === 0) {
      state.packets = snap.recent_packets.slice(-MAX_PACKETS).reverse();
      renderPackets();
    }
  }

  function verdictClass(verdict) {
    const v = String(verdict || "Pass").toLowerCase();
    if (v === "desync") return "verdict-chip v-desync";
    if (v === "modify") return "verdict-chip v-modify";
    if (v === "reasm") return "verdict-chip v-reasm";
    return "verdict-chip";
  }

  function renderPackets() {
    const list = $("packet-list");
    const q = state.filter.trim().toLowerCase();
    const visible = state.packets.filter((p) => {
      if (!q) return true;
      return (
        String(p.dst || "").toLowerCase().includes(q) ||
        String(p.info || "").toLowerCase().includes(q) ||
        String(p.verdict || "").toLowerCase().includes(q) ||
        String(p.profile || "").toLowerCase().includes(q)
      );
    });

    list.replaceChildren();
    if (visible.length === 0) {
      const empty = document.createElement("p");
      empty.className = "empty-note";
      empty.textContent = q ? "No packets match this filter." : "No packets captured yet.";
      list.appendChild(empty);
      return;
    }

    visible.forEach((p) => {
      const row = document.createElement("div");
      row.className = "pkt-row";

      const badge = document.createElement("span");
      badge.className = verdictClass(p.verdict);
      badge.textContent = String(p.verdict || "Pass").toUpperCase();

      const main = document.createElement("div");
      main.className = "pkt-main";
      const top = document.createElement("div");
      top.className = "mono";
      top.textContent = (p.proto || "") + " " + (p.dst || "") + (p.profile ? " (" + p.profile + ")" : "");
      const sub = document.createElement("div");
      sub.className = "pkt-sub mono";
      sub.textContent = "#" + p.seq + " " + (p.info || "");
      main.appendChild(top);
      main.appendChild(sub);

      const len = document.createElement("span");
      len.className = "muted mono";
      len.textContent = p.payload_len + "B";

      row.appendChild(badge);
      row.appendChild(main);
      row.appendChild(len);
      list.appendChild(row);
    });
  }

  function closeSse() {
    if (state.sse) {
      state.sse.close();
      state.sse = null;
    }
    $("sse-badge").textContent = "SSE off";
  }

  function connectSse() {
    closeSse();
    const es = new EventSource("/api/events");
    state.sse = es;
    $("sse-badge").textContent = "SSE live";

    es.addEventListener("status", (ev) => {
      try { applyStatusSnapshot(JSON.parse(ev.data)); } catch (_) {}
    });
    es.addEventListener("counters", (ev) => {
      try { updateCounters(JSON.parse(ev.data)); } catch (_) {}
    });
    es.addEventListener("packet", (ev) => {
      if (state.paused) return;
      try {
        const rec = JSON.parse(ev.data);
        state.packets.unshift(rec);
        if (state.packets.length > MAX_PACKETS) {
          state.packets.length = MAX_PACKETS;
        }
        renderPackets();
      } catch (_) {}
    });
    es.addEventListener("scan", (ev) => {
      try { applyScanSnapshot(JSON.parse(ev.data)); } catch (_) {}
    });
    es.onerror = () => {
      $("sse-badge").textContent = "SSE retry";
    };
  }

  function applyScanSnapshot(scan) {
    if (!scan) return;
    const running = scan.status === "running";
    $("scan-start-btn").disabled = running;
    $("scan-stop-btn").disabled = !running;
    $("scan-label").textContent = scan.label || "Ready to scan";
    const pct = scan.progress_total > 0 ? Math.min(100, Math.round((scan.progress_done * 100) / scan.progress_total)) : (scan.status === "done" ? 100 : 0);
    $("scan-bar").style.width = pct + "%";
    $("scan-count").textContent = scan.progress_total > 0 ? (scan.progress_done + "/" + scan.progress_total) : "";

    const resBox = $("scan-results");
    resBox.replaceChildren();
    (scan.targets || []).forEach((t) => {
      const row = document.createElement("div");
      row.className = "pkt-row";
      const badge = document.createElement("span");
      badge.className = t.best_strategy ? "verdict-chip v-desync" : "verdict-chip";
      badge.textContent = t.skipped ? "OPEN" : (t.best_strategy ? "MATCH" : "NONE");
      const main = document.createElement("div");
      main.className = "pkt-main mono";
      main.textContent = t.domain + " (" + t.proto + "/" + t.ipv + ") -> " + (t.best_strategy || t.baseline);
      const lat = document.createElement("span");
      lat.className = "muted mono";
      lat.textContent = t.best_latency_ms != null ? (t.best_latency_ms + " ms") : "";
      row.appendChild(badge);
      row.appendChild(main);
      row.appendChild(lat);
      resBox.appendChild(row);
    });
    state.foundToml = scan.rendered_toml || "";
    $("scan-toml-actions").classList.toggle("hidden", !state.foundToml);
  }

  function renderDomainRows(box, items, listName, emptyText) {
    box.replaceChildren();
    if (items.length === 0) {
      const p = document.createElement("p");
      p.className = "empty-note";
      p.textContent = emptyText;
      box.appendChild(p);
      return;
    }
    items.forEach((d) => {
      const row = document.createElement("div");
      row.className = "domain-row";
      const txt = document.createElement("span");
      txt.className = "mono";
      txt.textContent = d;
      const rm = document.createElement("button");
      rm.type = "button";
      rm.className = "btn btn-ghost btn-compact";
      rm.textContent = "Remove";
      rm.addEventListener("click", () => mutateDomain(d, "remove", listName));
      row.appendChild(txt);
      row.appendChild(rm);
      box.appendChild(row);
    });
  }

  async function loadDomains() {
    try {
      const data = await apiFetch("/api/domains");
      renderDomainRows(
        $("blacklist-chips"),
        data.exclude_domains || [],
        "exclude",
        "No excluded domains yet."
      );
      const autoOn = Boolean(data.autohostlist_enabled);
      $("domain-add-form").classList.toggle("hidden", !autoOn);
      $("autolist-path").textContent = autoOn
        ? (data.autohostlist_path || "")
        : "Auto Hostlist is off (set Domain Scope to Auto Hostlist to enable).";
      renderDomainRows(
        $("autolist-chips"),
        data.autohostlist_domains || [],
        "auto",
        autoOn ? "No autohostlist domains yet." : "Enable hostlist_auto on profiles to learn or edit entries."
      );
      const inline = $("inline-domains-chips");
      inline.replaceChildren();
      (data.hostlist_domains || []).forEach((d) => {
        const chip = document.createElement("span");
        chip.className = "chip mono";
        chip.textContent = d;
        inline.appendChild(chip);
      });
    } catch (err) {
      showToast(err.message);
    }
  }

  async function mutateDomain(domain, action, list) {
    try {
      await apiFetch("/api/domains", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain, action, list })
      });
      const verb = action === "add" ? (list === "exclude" ? "Blacklisted " : "Added ") : "Removed ";
      showToast(verb + domain);
      await loadDomains();
    } catch (err) {
      showToast(err.message);
    }
  }

  async function loadConfig() {
    try {
      const data = await apiFetch("/api/config");
      $("config-path-label").textContent = data.path || "";
      $("config-editor").value = data.toml || "";
      const chip = $("config-valid-chip");
      chip.textContent = data.valid ? ("VALID (" + data.profiles + " profiles)") : "INVALID";
      $("config-error").textContent = data.error || "";
      $("config-error").classList.toggle("hidden", !data.error);
    } catch (err) {
      showToast(err.message);
    }
  }

  async function saveConfig(apply, explicitToml) {
    $("config-error").classList.add("hidden");
    const tomlText = explicitToml != null ? explicitToml : $("config-editor").value;
    try {
      const res = await apiFetch("/api/config", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ toml: tomlText, apply })
      });
      showToast(apply ? (res.applied || "Saved & applied") : "Config saved");
      await loadConfig();
    } catch (err) {
      $("config-error").textContent = err.message;
      $("config-error").classList.remove("hidden");
      showToast(err.message);
    }
  }

  async function runSpeedTest() {
    const btn = $("speed-run-btn");
    btn.disabled = true;
    const rawDomains = ($("scan-domains").value || "").split(/[\s,]+/).filter(Boolean);
    try {
      const res = await apiFetch("/api/speed", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domains: rawDomains, include_control: true })
      });
      const box = $("speed-results");
      box.replaceChildren();
      (res.rows || []).forEach((r) => {
        const row = document.createElement("div");
        row.className = "pkt-row";
        const badge = document.createElement("span");
        badge.className = r.ok ? "verdict-chip v-desync" : "verdict-chip";
        badge.textContent = r.ok ? "OK" : "FAIL";
        const main = document.createElement("div");
        main.className = "pkt-main mono";
        main.textContent = r.label + "  " + r.summary;
        const speed = document.createElement("span");
        speed.className = "muted mono";
        speed.textContent = r.bytes_per_sec > 0 ? ((r.bytes_per_sec / 1000000).toFixed(2) + " MB/s") : ("ttfb " + r.ttfb_ms + " ms");
        row.appendChild(badge);
        row.appendChild(main);
        row.appendChild(speed);
        box.appendChild(row);
      });
      showToast("Speed test finished");
    } catch (err) {
      showToast(err.message);
    } finally {
      btn.disabled = false;
    }
  }

  function hideStopConfirm() {
    $("stop-confirm-row").classList.add("hidden");
    $("stop-ask-btn").classList.remove("hidden");
  }

  function bindNav() {
    document.querySelectorAll(".nav-item").forEach((btn) => {
      btn.addEventListener("click", () => {
        const tab = btn.getAttribute("data-tab");
        document.querySelectorAll(".nav-item").forEach((b) => b.classList.remove("active"));
        document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
        btn.classList.add("active");
        const panel = $("tab-" + tab);
        if (panel) panel.classList.add("active");
        if (tab === "domains") loadDomains();
        if (tab === "config") loadConfig();
      });
    });
  }

  function bindControls() {
    $("login-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      $("login-error").classList.add("hidden");
      const token = $("passcode-input").value.trim();
      if (!token) {
        $("login-error").textContent = "Enter the pairing passcode shown in the host terminal.";
        $("login-error").classList.remove("hidden");
        $("passcode-input").focus();
        return;
      }
      try {
        await apiFetch("/api/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ token })
        });
        $("passcode-input").value = "";
        showLogin(false);
        await bootSession();
      } catch (err) {
        $("login-error").textContent = err.message;
        $("login-error").classList.remove("hidden");
        $("passcode-input").focus();
        $("passcode-input").select();
      }
    });

    $("logout-btn").addEventListener("click", async () => {
      try {
        await fetch("/api/logout", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: "{}"
        });
      } finally {
        showLogin(true);
      }
    });

    $("reload-lists-btn").addEventListener("click", async () => {
      const btn = $("reload-lists-btn");
      btn.disabled = true;
      try {
        const res = await apiFetch("/api/daemon/reload-lists", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: "{}"
        });
        showToast(res.message || "Lists reloaded");
      } catch (err) {
        showToast(err.message);
      } finally {
        btn.disabled = !state.connected;
      }
    });

    $("stop-ask-btn").addEventListener("click", () => {
      $("stop-ask-btn").classList.add("hidden");
      $("stop-confirm-row").classList.remove("hidden");
    });

    $("stop-cancel-btn").addEventListener("click", hideStopConfirm);

    $("stop-confirm-btn").addEventListener("click", async () => {
      hideStopConfirm();
      try {
        const res = await apiFetch("/api/daemon/stop", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: "{}"
        });
        showToast(res.message || "Stop requested");
      } catch (err) {
        showToast(err.message);
      }
    });

    $("pause-feed-btn").addEventListener("click", () => {
      state.paused = !state.paused;
      $("pause-feed-btn").textContent = state.paused ? "Resume" : "Pause";
    });

    $("pkt-filter").addEventListener("input", (e) => {
      state.filter = e.target.value || "";
      renderPackets();
    });

    $("domains-refresh-btn").addEventListener("click", loadDomains);
    $("blacklist-add-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const input = $("blacklist-add-input");
      const val = input.value.trim();
      if (!val) return;
      input.value = "";
      await mutateDomain(val, "add", "exclude");
    });
    $("domain-add-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const input = $("domain-add-input");
      const val = input.value.trim();
      if (!val) return;
      input.value = "";
      await mutateDomain(val, "add", "auto");
    });

    $("config-reload-btn").addEventListener("click", loadConfig);
    $("config-save-btn").addEventListener("click", () => saveConfig(false));
    $("config-apply-btn").addEventListener("click", () => saveConfig(true));
    $("apply-scan-toml-btn").addEventListener("click", () => {
      if (state.foundToml) saveConfig(true, state.foundToml);
    });

    $("scan-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const domains = ($("scan-domains").value || "").split(/[\s,]+/).filter(Boolean);
      const protos = Array.from(document.querySelectorAll('input[name="proto"]:checked')).map((el) => el.value);
      try {
        const snap = await apiFetch("/api/scan/start", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            domains,
            protos,
            level: $("scan-level").value,
            stop_on_first: $("scan-stop-first").checked
          })
        });
        applyScanSnapshot(snap);
      } catch (err) {
        showToast(err.message);
      }
    });

    $("scan-stop-btn").addEventListener("click", async () => {
      try {
        await apiFetch("/api/scan/stop", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: "{}"
        });
        showToast("Scan stop requested");
      } catch (err) {
        showToast(err.message);
      }
    });

    $("speed-run-btn").addEventListener("click", runSpeedTest);
  }

  async function bootSession() {
    try {
      const res = await fetch("/api/auth/check");
      const info = await res.json();
      state.authRequired = Boolean(info.auth_required);
      $("logout-btn").classList.toggle("hidden", !state.authRequired);
      if (!info.authenticated) {
        showLogin(true);
        return;
      }
      showLogin(false);
      const snap = await apiFetch("/api/status");
      applyStatusSnapshot(snap);
      const scan = await apiFetch("/api/scan");
      applyScanSnapshot(scan);
      connectSse();
    } catch (_) {
      showLogin(true);
    }
  }

  bindNav();
  bindControls();
  bootSession();
})();
