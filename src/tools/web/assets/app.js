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
    if (res.status === 401) {
      showLogin(true);
      throw new Error("Authentication required");
    }
    const text = await res.text();
    let data = {};
    try { data = text ? JSON.parse(text) : {}; } catch (_) {}
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
    es.onerror = () => {
      $("sse-badge").textContent = "SSE retry";
    };
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
      });
    });
  }

  function bindControls() {
    $("login-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      $("login-error").classList.add("hidden");
      try {
        await apiFetch("/api/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ token: $("passcode-input").value })
        });
        $("passcode-input").value = "";
        showLogin(false);
        await bootSession();
      } catch (err) {
        $("login-error").textContent = err.message;
        $("login-error").classList.remove("hidden");
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
      connectSse();
    } catch (_) {
      showLogin(true);
    }
  }

  bindNav();
  bindControls();
  bootSession();
})();
