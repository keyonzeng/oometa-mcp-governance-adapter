/* mcp-control-plane — dashboard SPA. Vanilla JS, no build step. */
(() => {
  "use strict";

  // ------------------------------------------------------------------ //
  //  fetch wrapper
  // ------------------------------------------------------------------ //
  const TOKEN_KEY = "mcpcp_token";
  const getToken = () => localStorage.getItem(TOKEN_KEY) || "";

  async function api(path, { method = "GET", body } = {}) {
    const headers = { "Content-Type": "application/json" };
    const tok = getToken();
    if (tok) headers["Authorization"] = `Bearer ${tok}`;
    let res;
    try {
      res = await fetch(path, {
        method,
        headers,
        body: body != null ? JSON.stringify(body) : undefined,
      });
    } catch (e) {
      throw new Error(`Network error: ${e.message}`);
    }
    if (!res.ok) {
      let detail = `${res.status} ${res.statusText}`;
      try {
        const j = await res.json();
        if (j && j.detail) detail = typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail);
      } catch (_) {}
      const err = new Error(detail);
      err.status = res.status;
      throw err;
    }
    if (res.status === 204) return null;
    const ct = res.headers.get("content-type") || "";
    return ct.includes("json") ? res.json() : res.text();
  }

  // ------------------------------------------------------------------ //
  //  tiny utilities
  // ------------------------------------------------------------------ //
  const $ = (sel, root = document) => root.querySelector(sel);
  const el = (tag, attrs = {}, children = []) => {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (v == null) continue;
      if (k === "class") n.className = v;
      else if (k === "html") n.innerHTML = v;
      else if (k === "text") n.textContent = v;
      else if (k.startsWith("on") && typeof v === "function") n.addEventListener(k.slice(2), v);
      else n.setAttribute(k, v);
    }
    (Array.isArray(children) ? children : [children]).forEach((c) => {
      if (c == null) return;
      n.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
    });
    return n;
  };
  const esc = (s) =>
    String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
    );

  const RISKS = ["info", "low", "medium", "high", "critical"];
  const RISK_HEX = { info: "#64748b", low: "#34d399", medium: "#f59e0b", high: "#f97316", critical: "#ef4444" };

  const riskBadge = (r) => {
    const risk = (r || "info").toLowerCase();
    return `<span class="badge risk-${risk}"><span class="dot"></span>${esc(risk)}</span>`;
  };
  const statusBadge = (s) => {
    const st = (s || "discovered").toLowerCase();
    return `<span class="badge status-${st}">${esc(st)}</span>`;
  };
  const effClass = (e) => `eff-${e == null ? "null" : e}`;

  function relTime(iso) {
    if (!iso) return "—";
    const t = typeof iso === "number" ? iso * 1000 : Date.parse(iso);
    if (isNaN(t)) return esc(iso);
    let d = Math.floor((Date.now() - t) / 1000);
    if (d < 0) d = 0;
    if (d < 5) return "just now";
    if (d < 60) return `${d}s ago`;
    if (d < 3600) return `${Math.floor(d / 60)}m ago`;
    if (d < 86400) return `${Math.floor(d / 3600)}h ago`;
    if (d < 2592000) return `${Math.floor(d / 86400)}d ago`;
    return new Date(t).toLocaleDateString();
  }

  function jsonHighlight(obj) {
    let s;
    try { s = JSON.stringify(obj, null, 2); } catch (_) { s = String(obj); }
    return esc(s)
      .replace(/&quot;([^&]+)&quot;(\s*:)/g, '<span class="k">&quot;$1&quot;</span>$2')
      .replace(/: (&quot;[^&]*&quot;)/g, ': <span class="s">$1</span>')
      .replace(/: (-?\d+\.?\d*)/g, ': <span class="n">$1</span>')
      .replace(/: (true|false|null)/g, ': <span class="b">$1</span>');
  }

  // ------------------------------------------------------------------ //
  //  toasts
  // ------------------------------------------------------------------ //
  function toast(msg, kind = "info") {
    const ico = kind === "err" ? "⚠" : kind === "ok" ? "✓" : "ℹ";
    const t = el("div", { class: `toast ${kind}` }, [
      el("span", { text: ico, class: "opacity-80" }),
      el("span", { text: msg }),
    ]);
    $("#toasts").appendChild(t);
    setTimeout(() => {
      t.style.transition = "opacity .3s, transform .3s";
      t.style.opacity = "0";
      t.style.transform = "translateY(8px)";
      setTimeout(() => t.remove(), 300);
    }, kind === "err" ? 6000 : 3500);
  }

  // ------------------------------------------------------------------ //
  //  loading / empty helpers
  // ------------------------------------------------------------------ //
  const skeletonRows = (rows = 5, cols = 6) =>
    `<table class="dtable"><tbody>${Array.from({ length: rows }).map(() =>
      `<tr>${Array.from({ length: cols }).map(() =>
        `<td><div class="skeleton h-4 w-full"></div></td>`).join("")}</tr>`).join("")}</tbody></table>`;

  const emptyState = (big, title, sub = "") =>
    `<div class="empty"><div class="big">${big}</div><div class="font-medium text-[var(--text-dim)]">${esc(title)}</div>${sub ? `<div class="text-[12px] mt-1">${esc(sub)}</div>` : ""}</div>`;

  const errorState = (msg) =>
    `<div class="empty"><div class="big">⚠</div><div class="font-medium text-[#fca5a5]">Failed to load</div><div class="text-[12px] mt-1 mono">${esc(msg)}</div></div>`;

  // ------------------------------------------------------------------ //
  //  drawer
  // ------------------------------------------------------------------ //
  function openDrawer(node) {
    const d = $("#drawer");
    d.innerHTML = "";
    d.appendChild(node);
    d.classList.add("open");
    $("#drawer-backdrop").classList.add("open");
  }
  function closeDrawer() {
    $("#drawer").classList.remove("open");
    $("#drawer-backdrop").classList.remove("open");
  }
  $("#drawer-backdrop").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });

  // ------------------------------------------------------------------ //
  //  views registry
  // ------------------------------------------------------------------ //
  const VIEWS = {
    overview: { label: "Overview", sub: "The governance & security control plane for MCP", icon: icoGrid, render: renderOverview },
    servers:  { label: "Servers",  sub: "Registered MCP servers, ranked by risk",        icon: icoServer, render: renderServers },
    approvals:{ label: "Approvals",sub: "Human-in-the-loop tool-call approvals",          icon: icoCheck,  render: renderApprovals },
    audit:    { label: "Audit",    sub: "Tamper-evident, hash-chained event log",         icon: icoList,   render: renderAudit },
    policy:   { label: "Policy",   sub: "Rules & explainable decisions",                  icon: icoShield, render: renderPolicy },
    scan:     { label: "Scan",     sub: "Static risk scan of your MCP configuration",     icon: icoRadar,  render: renderScan },
  };

  let current = "overview";
  let overviewTimer = null;

  function buildNav() {
    const nav = $("#nav");
    nav.innerHTML = "";
    for (const [key, v] of Object.entries(VIEWS)) {
      const item = el("div", { class: "nav-item" + (key === current ? " active" : ""), onclick: () => go(key) }, [
        el("span", { class: "nav-ico", html: v.icon() }),
        el("span", { text: v.label }),
      ]);
      item.dataset.view = key;
      nav.appendChild(item);
    }
  }

  function go(key) {
    if (!VIEWS[key]) key = "overview";
    current = key;
    if (location.hash !== "#" + key) location.hash = key;
    document.querySelectorAll(".nav-item").forEach((n) => n.classList.toggle("active", n.dataset.view === key));
    const v = VIEWS[key];
    $("#view-title").textContent = v.label;
    $("#view-sub").textContent = v.sub;
    if (overviewTimer) { clearInterval(overviewTimer); overviewTimer = null; }
    const main = $("#view");
    main.innerHTML = "";
    v.render(main);
  }

  // ------------------------------------------------------------------ //
  //  OVERVIEW
  // ------------------------------------------------------------------ //
  async function renderOverview(root) {
    root.innerHTML = `
      <div class="fade-in space-y-6">
        <div id="ov-stats" class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3"></div>
        <div class="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div class="panel p-5 lg:col-span-1" id="ov-chain"></div>
          <div class="panel p-5 lg:col-span-2" id="ov-risk"></div>
        </div>
      </div>`;
    const statsBox = $("#ov-stats", root);
    statsBox.innerHTML = Array.from({ length: 5 }).map(() => `<div class="stat"><div class="skeleton h-8 w-16 mb-3"></div><div class="skeleton h-3 w-24"></div></div>`).join("");

    async function load() {
      try {
        const [stats, verify, servers] = await Promise.all([
          api("/api/stats"),
          api("/api/audit/verify").catch(() => null),
          api("/api/servers").catch(() => []),
        ]);
        paintStats(statsBox, stats);
        paintChain($("#ov-chain", root), verify, stats);
        paintRisk($("#ov-risk", root), servers);
      } catch (e) {
        statsBox.innerHTML = errorState(e.message);
        toast("Could not load overview: " + e.message, "err");
      }
    }
    await load();
    overviewTimer = setInterval(() => { if (current === "overview") load(); }, 10000);
  }

  function paintStats(box, s) {
    const cards = [
      ["Servers", s.servers, "registered"],
      ["Approved", s.approved, "active servers"],
      ["Pending review", s.pending_servers, "awaiting triage"],
      ["Pending approvals", s.pending_approvals, "call requests"],
      ["Audit events", s.audit_events, "logged"],
    ];
    box.innerHTML = cards.map(([lbl, val, sub]) =>
      `<div class="stat fade-in"><div class="stat-val">${val ?? 0}</div><div class="stat-lbl">${lbl}</div><div class="text-[11px] text-[var(--text-mute)] mt-0.5">${sub}</div></div>`
    ).join("");
  }

  function paintChain(box, verify, stats) {
    const ok = verify ? verify.ok : stats.audit_chain_ok;
    const brokenAt = verify ? verify.broken_at : stats.audit_chain_broken_at;
    box.innerHTML = `
      <div class="text-[11px] uppercase tracking-wide text-[var(--text-mute)] font-semibold mb-3">Audit chain integrity</div>
      <div class="flex items-center gap-3">
        <div class="w-11 h-11 rounded-xl flex items-center justify-center" style="background:${ok ? "rgba(52,211,153,.16)" : "rgba(239,68,68,.16)"}">
          <span style="font-size:22px">${ok ? "🔒" : "⛓️‍💥"}</span>
        </div>
        <div>
          <div class="text-lg font-bold ${ok ? "text-[#6ee7b7]" : "text-[#fca5a5]"}">${ok ? "OK" : "BROKEN"}</div>
          <div class="text-[12px] text-[var(--text-dim)]">${ok ? "Hash chain verified end-to-end" : "Tampering detected at " + esc(brokenAt || "?")}</div>
        </div>
      </div>
      <div class="text-[11px] text-[var(--text-mute)] mt-4 leading-snug">Every audit event embeds the hash of its predecessor. Any edit breaks the chain.</div>`;
  }

  function paintRisk(box, servers) {
    const counts = Object.fromEntries(RISKS.map((r) => [r, 0]));
    servers.forEach((s) => { const r = (s.risk || "info").toLowerCase(); if (counts[r] != null) counts[r]++; });
    const total = servers.length || 0;
    const bar = total === 0
      ? `<div class="riskbar"><span style="width:100%;background:#1a2433"></span></div>`
      : `<div class="riskbar">${RISKS.map((r) => counts[r] ? `<span title="${r}: ${counts[r]}" style="width:${(counts[r] / total) * 100}%;background:${RISK_HEX[r]}"></span>` : "").join("")}</div>`;
    box.innerHTML = `
      <div class="flex items-center justify-between mb-3">
        <div class="text-[11px] uppercase tracking-wide text-[var(--text-mute)] font-semibold">Server risk distribution</div>
        <div class="text-[12px] text-[var(--text-dim)]">${total} server${total === 1 ? "" : "s"}</div>
      </div>
      ${bar}
      <div class="flex flex-wrap gap-x-5 gap-y-2 mt-4">
        ${RISKS.map((r) => `<div class="flex items-center gap-2 text-[12px]"><span class="w-2.5 h-2.5 rounded-sm" style="background:${RISK_HEX[r]}"></span><span class="text-[var(--text-dim)] capitalize">${r}</span><span class="mono text-[var(--text)]">${counts[r]}</span></div>`).join("")}
      </div>`;
  }

  // ------------------------------------------------------------------ //
  //  SERVERS
  // ------------------------------------------------------------------ //
  async function renderServers(root) {
    root.innerHTML = `
      <div class="fade-in">
        <div class="flex items-center justify-between mb-4 gap-3 flex-wrap">
          <div class="flex items-center gap-2" id="srv-filters"></div>
          <div class="text-[12px] text-[var(--text-mute)]" id="srv-count"></div>
        </div>
        <div class="panel-flat overflow-hidden"><div id="srv-table">${skeletonRows(6, 7)}</div></div>
      </div>`;
    const filters = ["all", "discovered", "pending", "approved", "rejected", "disabled"];
    let activeFilter = "all";
    const fbox = $("#srv-filters", root);
    fbox.innerHTML = filters.map((f) => `<button class="btn btn-sm ${f === "all" ? "btn-primary" : ""}" data-f="${f}" style="text-transform:capitalize">${f}</button>`).join("");

    async function load() {
      const tbl = $("#srv-table", root);
      tbl.innerHTML = skeletonRows(6, 7);
      try {
        const qs = activeFilter === "all" ? "" : `?status=${activeFilter}`;
        const servers = await api("/api/servers" + qs);
        servers.sort((a, b) => (b.risk_score ?? 0) - (a.risk_score ?? 0));
        $("#srv-count", root).textContent = `${servers.length} server${servers.length === 1 ? "" : "s"}`;
        if (!servers.length) { tbl.innerHTML = emptyState("📭", "No servers", activeFilter === "all" ? "Run a scan or register a server." : `No servers with status “${activeFilter}”.`); return; }
        tbl.innerHTML = `
          <table class="dtable">
            <thead><tr>
              <th>Risk</th><th>Name</th><th>Transport</th><th>Source</th><th>Status</th><th class="text-center">Tools</th><th class="text-right">Score</th>
            </tr></thead>
            <tbody>
              ${servers.map((s) => `
                <tr class="clickable" data-id="${esc(s.id)}">
                  <td>${riskBadge(s.risk)}</td>
                  <td><div class="font-medium">${esc(s.name)}</div><div class="text-[11px] text-[var(--text-mute)] truncate max-w-[280px]">${esc(s.description || (s.command ? s.command + " " + (s.args || []).join(" ") : s.url || ""))}</div></td>
                  <td class="mono text-[12px] text-[var(--text-dim)]">${esc(s.transport || "—")}</td>
                  <td class="text-[12px] text-[var(--text-dim)]">${esc(s.source || "—")}</td>
                  <td>${statusBadge(s.status)}</td>
                  <td class="text-center mono">${(s.tools || []).length}</td>
                  <td class="text-right"><span class="mono font-semibold" style="color:${RISK_HEX[(s.risk||'info').toLowerCase()]}">${s.risk_score ?? 0}</span></td>
                </tr>`).join("")}
            </tbody>
          </table>`;
        tbl.querySelectorAll("tr.clickable").forEach((tr) =>
          tr.addEventListener("click", () => openServerDrawer(tr.dataset.id, load)));
      } catch (e) {
        tbl.innerHTML = errorState(e.message);
        toast("Could not load servers: " + e.message, "err");
      }
    }
    fbox.querySelectorAll("button").forEach((b) =>
      b.addEventListener("click", () => {
        activeFilter = b.dataset.f;
        fbox.querySelectorAll("button").forEach((x) => x.classList.toggle("btn-primary", x === b));
        load();
      }));
    await load();
  }

  async function openServerDrawer(id, onChange) {
    openDrawer(el("div", { class: "p-6", html: `<div class="skeleton h-6 w-40 mb-4"></div>${skeletonRows(4, 1)}` }));
    let s;
    try { s = await api(`/api/servers/${id}`); }
    catch (e) { toast("Could not load server: " + e.message, "err"); closeDrawer(); return; }

    const toolsHtml = (s.tools || []).length ? (s.tools || []).map((t) => `
      <div class="panel-flat p-3 mb-2">
        <div class="flex items-center justify-between gap-2">
          <div class="font-medium mono text-[13px]">${esc(t.name)}</div>
          ${riskBadge(t.risk)}
        </div>
        ${t.description ? `<div class="text-[12px] text-[var(--text-dim)] mt-1">${esc(t.description)}</div>` : ""}
        ${(t.capabilities || []).length ? `<div class="flex flex-wrap gap-1.5 mt-2">${t.capabilities.map((c) => `<span class="chip">${esc(c)}</span>`).join("")}</div>` : ""}
        ${(t.findings || []).length ? `<div class="mt-2 space-y-1">${t.findings.map((f) => `<div class="flex gap-2 text-[12px] text-[#fca5a5]"><span>⚠</span><span>${esc(f)}</span></div>`).join("")}</div>` : ""}
      </div>`).join("") : `<div class="text-[12px] text-[var(--text-mute)]">No tools advertised.</div>`;

    const factorsHtml = (s.risk_factors || []).length
      ? `<ul class="space-y-1.5">${s.risk_factors.map((f) => `<li class="flex gap-2 text-[13px]"><span class="text-[var(--text-mute)]">›</span><span>${esc(f)}</span></li>`).join("")}</ul>`
      : `<div class="text-[12px] text-[var(--text-mute)]">No notable risk factors.</div>`;

    const cfHtml = (s.config_findings || []).length
      ? `<div>
          <div class="text-[11px] uppercase tracking-wide text-[var(--text-mute)] font-semibold mb-2">Static config findings (scanner)</div>
          <div class="space-y-2">${s.config_findings.map((f) => `
            <div class="panel-flat p-3">
              <div class="flex items-center gap-2 mb-1">${riskBadge(f.severity)}<span class="mono text-[12px] font-semibold">${esc(f.code || "")}</span><span class="text-[13px]">${esc(f.title || "")}</span></div>
              ${f.detail ? `<div class="text-[12px] text-[var(--text-dim)]">${esc(f.detail)}</div>` : ""}
              ${f.remediation ? `<div class="text-[12px] text-[var(--text-mute)] mt-1">↳ ${esc(f.remediation)}</div>` : ""}
            </div>`).join("")}</div>
        </div>`
      : "";

    const node = el("div", { class: "flex flex-col h-full" });
    node.innerHTML = `
      <div class="flex items-start justify-between gap-3 p-6 border-b border-[var(--border)]">
        <div class="min-w-0">
          <div class="flex items-center gap-2 mb-1.5">${riskBadge(s.risk)} ${statusBadge(s.status)}</div>
          <h2 class="text-lg font-semibold truncate">${esc(s.name)}</h2>
          <div class="text-[11px] text-[var(--text-mute)] mono mt-0.5 truncate">${esc(s.id)}</div>
        </div>
        <button id="drawer-close" class="btn btn-sm">✕</button>
      </div>
      <div class="flex-1 overflow-y-auto p-6 space-y-5">
        ${s.description ? `<p class="text-[13px] text-[var(--text-dim)]">${esc(s.description)}</p>` : ""}
        <div class="grid grid-cols-2 gap-3 text-[12px]">
          <div><div class="text-[var(--text-mute)] mb-0.5">Transport</div><div class="mono">${esc(s.transport || "—")}</div></div>
          <div><div class="text-[var(--text-mute)] mb-0.5">Source</div><div>${esc(s.source || "—")}</div></div>
          <div class="col-span-2"><div class="text-[var(--text-mute)] mb-0.5">Command</div><div class="mono break-all">${esc(s.command ? s.command + " " + (s.args || []).join(" ") : (s.url || "—"))}</div></div>
          ${(s.env_keys || []).length ? `<div class="col-span-2"><div class="text-[var(--text-mute)] mb-1">Env keys</div><div class="flex flex-wrap gap-1.5">${s.env_keys.map((k) => `<span class="chip mono">${esc(k)}</span>`).join("")}</div></div>` : ""}
          ${(s.tags || []).length ? `<div class="col-span-2"><div class="text-[var(--text-mute)] mb-1">Tags</div><div class="flex flex-wrap gap-1.5">${s.tags.map((k) => `<span class="chip">${esc(k)}</span>`).join("")}</div></div>` : ""}
        </div>
        <div>
          <div class="flex items-center justify-between mb-2"><div class="text-[11px] uppercase tracking-wide text-[var(--text-mute)] font-semibold">Risk factors</div><span class="mono text-[13px] font-semibold" style="color:${RISK_HEX[(s.risk||'info').toLowerCase()]}">score ${s.risk_score ?? 0}</span></div>
          ${factorsHtml}
        </div>
        ${cfHtml}
        <div>
          <div class="text-[11px] uppercase tracking-wide text-[var(--text-mute)] font-semibold mb-2">Tools (${(s.tools || []).length})</div>
          ${toolsHtml}
        </div>
        <div class="text-[11px] text-[var(--text-mute)] flex gap-4 pt-1">
          <span>created ${relTime(s.created_at)}</span><span>updated ${relTime(s.updated_at)}</span>${s.reviewed_by ? `<span>by ${esc(s.reviewed_by)}</span>` : ""}
        </div>
      </div>
      <div class="p-4 border-t border-[var(--border)] flex gap-2">
        <button class="btn btn-approve btn-sm flex-1" data-act="approve">Approve</button>
        <button class="btn btn-deny btn-sm flex-1" data-act="reject">Reject</button>
        <button class="btn btn-warn btn-sm flex-1" data-act="disable">Disable</button>
      </div>`;
    node.querySelector("#drawer-close").addEventListener("click", closeDrawer);
    node.querySelectorAll("[data-act]").forEach((b) =>
      b.addEventListener("click", async () => {
        const act = b.dataset.act;
        b.disabled = true; b.textContent = "…";
        try {
          await api(`/api/servers/${id}/${act}`, { method: "POST", body: { by: "dashboard", note: null } });
          toast(`Server ${act}d`, "ok");
          closeDrawer();
          if (onChange) onChange();
        } catch (e) {
          toast(`Failed to ${act}: ${e.message}`, "err");
          b.disabled = false; b.textContent = act[0].toUpperCase() + act.slice(1);
        }
      }));
    openDrawer(node);
  }

  // ------------------------------------------------------------------ //
  //  APPROVALS
  // ------------------------------------------------------------------ //
  async function renderApprovals(root) {
    root.innerHTML = `<div class="fade-in"><div id="appr-box" class="grid grid-cols-1 lg:grid-cols-2 gap-4"></div></div>`;
    const box = $("#appr-box", root);
    box.innerHTML = Array.from({ length: 2 }).map(() => `<div class="panel p-5"><div class="skeleton h-5 w-40 mb-3"></div><div class="skeleton h-20 w-full"></div></div>`).join("");

    async function load() {
      try {
        const items = await api("/api/approvals?status=pending");
        if (!items.length) { box.innerHTML = `<div class="lg:col-span-2">${emptyState("🎉", "No pending approvals", "All caught up. Tool-call requests will show up here.")}</div>`; return; }
        box.innerHTML = "";
        items.forEach((a) => box.appendChild(approvalCard(a, load)));
      } catch (e) {
        box.innerHTML = `<div class="lg:col-span-2">${errorState(e.message)}</div>`;
        toast("Could not load approvals: " + e.message, "err");
      }
    }
    await load();
  }

  function approvalCard(a, onChange) {
    const card = el("div", { class: "panel p-5 fade-in flex flex-col" });
    card.innerHTML = `
      <div class="flex items-start justify-between gap-3 mb-3">
        <div class="min-w-0">
          <div class="flex items-center gap-2 mb-1">${riskBadge(a.risk)}<span class="text-[11px] text-[var(--text-mute)]">${relTime(a.requested_at)}</span></div>
          <div class="font-semibold mono text-[14px] truncate">${esc(a.server_name || "—")}<span class="text-[var(--text-mute)]">.</span>${esc(a.tool || "—")}</div>
        </div>
      </div>
      <div class="text-[12px] text-[var(--text-dim)] space-y-1 mb-3">
        <div><span class="text-[var(--text-mute)]">agent</span> <span class="mono">${esc(a.agent || "—")}</span>${a.principal ? ` <span class="text-[var(--text-mute)]">· principal</span> <span class="mono">${esc(a.principal)}</span>` : ""}</div>
        ${a.reason ? `<div class="text-[var(--text)]">${esc(a.reason)}</div>` : ""}
      </div>
      <div class="mb-4">
        <div class="text-[11px] uppercase tracking-wide text-[var(--text-mute)] font-semibold mb-1.5">Arguments</div>
        <pre class="json">${jsonHighlight(a.arguments_preview || {})}</pre>
      </div>
      <div class="flex gap-2 mt-auto">
        <button class="btn btn-approve btn-sm flex-1" data-d="1">Approve</button>
        <button class="btn btn-deny btn-sm flex-1" data-d="0">Deny</button>
      </div>`;
    card.querySelectorAll("[data-d]").forEach((b) =>
      b.addEventListener("click", async () => {
        const approve = b.dataset.d === "1";
        card.querySelectorAll("button").forEach((x) => (x.disabled = true));
        try {
          await api(`/api/approvals/${a.id}/decide`, { method: "POST", body: { approve, by: "dashboard", note: null } });
          toast(approve ? "Approved" : "Denied", "ok");
          if (onChange) onChange();
        } catch (e) {
          toast("Decision failed: " + e.message, "err");
          card.querySelectorAll("button").forEach((x) => (x.disabled = false));
        }
      }));
    return card;
  }

  // ------------------------------------------------------------------ //
  //  AUDIT
  // ------------------------------------------------------------------ //
  async function renderAudit(root) {
    root.innerHTML = `
      <div class="fade-in space-y-4">
        <div class="flex items-center justify-between gap-3 flex-wrap">
          <div id="audit-verify" class="text-[12px] text-[var(--text-mute)]">verifying chain…</div>
          <div class="flex items-center gap-2">
            <select id="audit-kind" class="inp btn-sm" style="width:auto;padding:6px 10px">
              <option value="">All kinds</option>
              <option value="decision">decision</option>
              <option value="approval">approval</option>
              <option value="registry">registry</option>
              <option value="scan">scan</option>
            </select>
          </div>
        </div>
        <div class="panel-flat overflow-hidden"><div id="audit-table">${skeletonRows(8, 6)}</div></div>
      </div>`;

    api("/api/audit/verify").then((v) => {
      $("#audit-verify", root).innerHTML = v.ok
        ? `<span class="badge status-approved">🔒 chain OK</span>`
        : `<span class="badge status-rejected">⛓️‍💥 broken at ${esc(v.broken_at || "?")}</span>`;
    }).catch(() => { $("#audit-verify", root).textContent = "chain status unavailable"; });

    async function load() {
      const tbl = $("#audit-table", root);
      tbl.innerHTML = skeletonRows(8, 6);
      const kind = $("#audit-kind", root).value;
      try {
        const events = await api(`/api/audit?limit=200${kind ? "&kind=" + encodeURIComponent(kind) : ""}`);
        if (!events.length) { tbl.innerHTML = emptyState("🗒️", "No audit events", "Activity will be recorded here as it happens."); return; }
        tbl.innerHTML = `
          <table class="dtable">
            <thead><tr><th>When</th><th>Kind</th><th>Subject</th><th>Effect</th><th>Outcome</th><th>Hash</th></tr></thead>
            <tbody>
              ${events.map((e) => `
                <tr>
                  <td class="text-[12px] text-[var(--text-dim)] whitespace-nowrap" title="${esc(e.timestamp)}">${relTime(e.timestamp)}</td>
                  <td><span class="chip">${esc(e.kind || "—")}</span></td>
                  <td class="text-[12px]"><span class="mono">${esc(e.server_name || "")}${e.tool ? "." + esc(e.tool) : ""}</span>${e.agent ? `<div class="text-[11px] text-[var(--text-mute)]">agent ${esc(e.agent)}</div>` : ""}${e.reason ? `<div class="text-[11px] text-[var(--text-mute)] truncate max-w-[260px]">${esc(e.reason)}</div>` : ""}</td>
                  <td class="text-[12px] font-semibold ${effClass(e.effect)}">${e.effect == null ? "—" : esc(e.effect)}</td>
                  <td class="text-[12px]">${e.outcome ? `<span class="${effClass(e.outcome === "allow" || e.outcome === "approved" || e.outcome === "ok" ? "allow" : (e.outcome === "deny" || e.outcome === "denied" || e.outcome === "error" ? "deny" : "require_approval"))}">${esc(e.outcome)}</span>` : "—"}</td>
                  <td class="mono text-[11px] text-[var(--text-mute)]" title="${esc(e.hash || "")}">${esc((e.hash || "").slice(0, 10) || "—")}</td>
                </tr>`).join("")}
            </tbody>
          </table>`;
      } catch (e) {
        tbl.innerHTML = errorState(e.message);
        toast("Could not load audit log: " + e.message, "err");
      }
    }
    $("#audit-kind", root).addEventListener("change", load);
    await load();
  }

  // ------------------------------------------------------------------ //
  //  POLICY
  // ------------------------------------------------------------------ //
  async function renderPolicy(root) {
    root.innerHTML = `
      <div class="fade-in grid grid-cols-1 xl:grid-cols-2 gap-5">
        <div class="space-y-4">
          <div class="panel p-5" id="pol-meta"><div class="skeleton h-6 w-40 mb-3"></div><div class="skeleton h-16 w-full"></div></div>
          <div class="panel-flat overflow-hidden"><div id="pol-rules">${skeletonRows(5, 4)}</div></div>
        </div>
        <div class="panel p-5 h-fit" id="pol-explain"></div>
      </div>`;

    let policy = null, servers = [];
    try {
      [policy, servers] = await Promise.all([api("/api/policy"), api("/api/servers").catch(() => [])]);
    } catch (e) {
      $("#pol-meta", root).innerHTML = errorState(e.message);
      toast("Could not load policy: " + e.message, "err");
      return;
    }

    $("#pol-meta", root).innerHTML = `
      <div class="flex items-start justify-between gap-3 mb-2">
        <div><div class="text-[11px] uppercase tracking-wide text-[var(--text-mute)] font-semibold mb-1">Active policy</div><h2 class="text-lg font-semibold">${esc(policy.name || "policy")}</h2></div>
        <div class="text-right"><div class="text-[10px] uppercase text-[var(--text-mute)] mb-1">default effect</div><span class="font-semibold ${effClass(policy.default_effect)}">${esc(policy.default_effect || "—")}</span></div>
      </div>
      ${policy.description ? `<p class="text-[13px] text-[var(--text-dim)]">${esc(policy.description)}</p>` : ""}
      ${policy.settings && Object.keys(policy.settings).length ? `<div class="mt-3 flex flex-wrap gap-1.5">${Object.entries(policy.settings).map(([k, v]) => `<span class="chip mono">${esc(k)}=${esc(typeof v === "object" ? JSON.stringify(v) : v)}</span>`).join("")}</div>` : ""}`;

    const rules = (policy.rules || []).slice().sort((a, b) => (b.priority ?? 0) - (a.priority ?? 0));
    $("#pol-rules", root).innerHTML = rules.length ? `
      <table class="dtable">
        <thead><tr><th class="w-16 text-right">Prio</th><th>Rule</th><th>Effect</th></tr></thead>
        <tbody>
          ${rules.map((r) => `
            <tr>
              <td class="text-right mono text-[var(--text-dim)]">${r.priority ?? 0}</td>
              <td><div class="mono text-[12px] font-medium">${esc(r.id)}</div><div class="text-[11px] text-[var(--text-mute)]">${esc(r.description || "")}</div>${r.reason ? `<div class="text-[11px] text-[var(--text-mute)] italic">${esc(r.reason)}</div>` : ""}</td>
              <td><span class="font-semibold text-[12px] ${effClass(r.effect)}">${esc(r.effect || "—")}</span></td>
            </tr>`).join("")}
        </tbody>
      </table>` : emptyState("📜", "No rules", "This policy relies on its default effect.");

    // explain form
    $("#pol-explain", root).innerHTML = `
      <div class="flex items-center gap-2 mb-1">
        <span class="text-[18px]">🧭</span>
        <h3 class="text-[15px] font-semibold">Explain a call</h3>
      </div>
      <p class="text-[12px] text-[var(--text-mute)] mb-4">Simulate a tool call and see exactly which rule decides it, and why.</p>
      <div class="space-y-3">
        <div>
          <label class="lbl">Server</label>
          <select id="ex-server" class="inp">${servers.length ? servers.map((s) => `<option value="${esc(s.name)}">${esc(s.name)} — ${esc(s.risk || "info")}</option>`).join("") : `<option value="">(no servers registered)</option>`}</select>
        </div>
        <div class="grid grid-cols-2 gap-3">
          <div><label class="lbl">Tool</label><input id="ex-tool" class="inp mono" placeholder="e.g. write_file" /></div>
          <div><label class="lbl">Agent</label><input id="ex-agent" class="inp mono" value="explorer" /></div>
        </div>
        <div><label class="lbl">Arguments (JSON)</label><textarea id="ex-args" class="inp mono" placeholder='{ "path": "/etc/passwd" }'>{}</textarea></div>
        <button id="ex-run" class="btn btn-primary w-full">Evaluate decision</button>
      </div>
      <div id="ex-result" class="mt-5"></div>`;

    $("#ex-run", root).addEventListener("click", async () => {
      const out = $("#ex-result", root);
      const serverName = $("#ex-server", root).value;
      const tool = $("#ex-tool", root).value.trim();
      const agent = $("#ex-agent", root).value.trim() || "explorer";
      if (!serverName) { toast("Register a server first to evaluate a call.", "err"); return; }
      if (!tool) { toast("Enter a tool name.", "err"); return; }
      let args = {};
      try { args = JSON.parse($("#ex-args", root).value || "{}"); }
      catch (e) { toast("Arguments are not valid JSON.", "err"); return; }

      const btn = $("#ex-run", root);
      btn.disabled = true; btn.textContent = "Evaluating…";
      out.innerHTML = `<div class="skeleton h-20 w-full"></div>`;
      try {
        const d = await api("/api/policy/evaluate", { method: "POST", body: { server_name: serverName, tool, arguments: args, agent } });
        out.innerHTML = renderDecision(d);
      } catch (e) {
        out.innerHTML = errorState(e.message);
        toast("Evaluation failed: " + e.message, "err");
      } finally {
        btn.disabled = false; btn.textContent = "Evaluate decision";
      }
    });
  }

  function renderDecision(d) {
    const eff = d.effect || "null";
    const ico = eff === "allow" ? "✓" : eff === "deny" ? "✕" : "⏸";
    const trace = d.trace || [];
    return `
      <div class="effect-hero ${eff} fade-in mb-4">
        <div class="eh-icon">${ico}</div>
        <div class="min-w-0">
          <div class="text-lg font-bold ${effClass(eff)}">${esc(eff.replace("_", " ").toUpperCase())}</div>
          <div class="text-[12px] text-[var(--text-dim)]">${esc(d.reason || "")}</div>
          <div class="flex items-center gap-2 mt-1.5 text-[11px] text-[var(--text-mute)]">
            ${d.matched_rule ? `matched <span class="mono text-[var(--text-dim)]">${esc(d.matched_rule)}</span>` : "no rule matched (default)"}
            ${d.risk ? `· ${riskBadge(d.risk)}` : ""}
          </div>
        </div>
      </div>
      ${(d.obligations || []).length ? `<div class="mb-4"><div class="text-[11px] uppercase tracking-wide text-[var(--text-mute)] font-semibold mb-1.5">Obligations</div><div class="flex flex-wrap gap-1.5">${d.obligations.map((o) => `<span class="chip danger">${esc(typeof o === "object" ? JSON.stringify(o) : o)}</span>`).join("")}</div></div>` : ""}
      <div class="text-[11px] uppercase tracking-wide text-[var(--text-mute)] font-semibold mb-2">Decision trace (${trace.length})</div>
      <div class="space-y-2">
        ${trace.length ? trace.map((t) => `
          <div class="trace-step ${t.matched ? "matched" : ""}">
            <div class="trace-rail"></div>
            <div class="min-w-0 flex-1">
              <div class="flex items-center justify-between gap-2">
                <span class="mono text-[12px] font-medium">${esc(t.rule || "—")}</span>
                <div class="flex items-center gap-2 flex-none">
                  ${t.priority != null ? `<span class="text-[11px] text-[var(--text-mute)] mono">p${t.priority}</span>` : ""}
                  <span class="text-[11px] font-semibold ${effClass(t.effect)}">${esc(t.effect || "—")}</span>
                  <span class="badge ${t.matched ? "status-approved" : "status-disabled"}" style="font-size:10px">${t.matched ? "matched" : "skipped"}</span>
                </div>
              </div>
              ${(t.why || []).length ? `<ul class="mt-1.5 space-y-0.5">${t.why.map((w) => `<li class="text-[11px] text-[var(--text-dim)] flex gap-1.5"><span class="text-[var(--text-mute)]">${t.matched ? "✓" : "·"}</span><span>${esc(w)}</span></li>`).join("")}</ul>` : ""}
            </div>
          </div>`).join("") : `<div class="text-[12px] text-[var(--text-mute)]">No trace returned — decision fell through to default effect.</div>`}
      </div>`;
  }

  // ------------------------------------------------------------------ //
  //  SCAN
  // ------------------------------------------------------------------ //
  async function renderScan(root) {
    root.innerHTML = `
      <div class="fade-in space-y-5">
        <div class="panel p-5 flex items-center justify-between gap-4 flex-wrap">
          <div>
            <h2 class="text-[15px] font-semibold">Configuration risk scan</h2>
            <p class="text-[12px] text-[var(--text-mute)] mt-0.5">Statically inspect discovered MCP servers for risky configuration. Fails on <span class="mono">high</span> or worse.</p>
          </div>
          <button id="scan-run" class="btn btn-primary">▶ Run scan</button>
        </div>
        <div id="scan-out"></div>
      </div>`;

    const out = $("#scan-out", root);
    out.innerHTML = emptyState("🛰️", "No scan yet", "Click “Run scan” to inspect your MCP configuration.");

    $("#scan-run", root).addEventListener("click", async () => {
      const btn = $("#scan-run", root);
      btn.disabled = true; btn.textContent = "Scanning…";
      out.innerHTML = `<div class="panel p-6">${skeletonRows(4, 1)}</div>`;
      try {
        const r = await api("/api/scan", { method: "POST", body: { include_user: true, project_root: null, fail_on: "high" } });
        out.innerHTML = renderScanReport(r);
      } catch (e) {
        out.innerHTML = errorState(e.message);
        toast("Scan failed: " + e.message, "err");
      } finally {
        btn.disabled = false; btn.textContent = "▶ Run scan";
      }
    });
  }

  function renderScanReport(r) {
    const counts = r.severity_counts || {};
    const passed = !!r.passed;
    const banner = `
      <div class="panel p-5 flex items-center gap-4" style="border-color:${passed ? "rgba(52,211,153,.4)" : "rgba(239,68,68,.45)"};background:${passed ? "rgba(52,211,153,.06)" : "rgba(239,68,68,.06)"}">
        <div class="w-12 h-12 rounded-xl flex items-center justify-center text-2xl" style="background:${passed ? "rgba(52,211,153,.16)" : "rgba(239,68,68,.16)"}">${passed ? "✓" : "✕"}</div>
        <div>
          <div class="text-lg font-bold ${passed ? "text-[#6ee7b7]" : "text-[#fca5a5]"}">${passed ? "PASSED" : "FAILED"}</div>
          <div class="text-[12px] text-[var(--text-dim)]">${r.servers_scanned ?? 0} server${r.servers_scanned === 1 ? "" : "s"} scanned · worst severity ${riskBadge(r.worst)}</div>
        </div>
      </div>`;

    const sevCards = `<div class="grid grid-cols-2 md:grid-cols-5 gap-3">${RISKS.map((sv) => `
      <div class="stat" style="padding:14px 16px">
        <div class="stat-val" style="color:${RISK_HEX[sv]}">${counts[sv] ?? 0}</div>
        <div class="stat-lbl capitalize">${sv}</div>
      </div>`).join("")}</div>`;

    const servers = r.servers || [];
    const serverCards = servers.length ? servers.map((s) => `
      <div class="panel p-5">
        <div class="flex items-start justify-between gap-3 mb-3">
          <div class="min-w-0">
            <div class="flex items-center gap-2 mb-1">${riskBadge(s.risk)}</div>
            <div class="font-semibold">${esc(s.name)}</div>
            <div class="text-[11px] text-[var(--text-mute)] mono truncate">${esc(s.source || "")}${s.transport ? " · " + esc(s.transport) : ""}${s.command ? " · " + esc(s.command) : ""}</div>
          </div>
        </div>
        ${(s.findings || []).length ? `<div class="space-y-2">${s.findings.map((f) => `
          <div class="panel-flat p-3" style="border-left:3px solid ${RISK_HEX[(f.severity||'info').toLowerCase()]}">
            <div class="flex items-center justify-between gap-2 mb-1">
              <div class="font-medium text-[13px]">${esc(f.title)}</div>
              ${riskBadge(f.severity)}
            </div>
            <div class="text-[11px] text-[var(--text-mute)] mono mb-1.5">${esc(f.code || "")}${f.config_path ? " · " + esc(f.config_path) : ""}</div>
            ${f.detail ? `<div class="text-[12px] text-[var(--text-dim)]">${esc(f.detail)}</div>` : ""}
            ${f.remediation ? `<div class="text-[12px] mt-1.5 flex gap-1.5"><span class="text-[#6ee7b7]">→</span><span class="text-[var(--text-dim)]">${esc(f.remediation)}</span></div>` : ""}
          </div>`).join("")}</div>` : `<div class="text-[12px] text-[#6ee7b7]">✓ No findings.</div>`}
      </div>`).join("") : emptyState("🛰️", "No servers found to scan", "");

    return `<div class="space-y-5 fade-in">${banner}${sevCards}<div class="grid grid-cols-1 lg:grid-cols-2 gap-4">${serverCards}</div></div>`;
  }

  // ------------------------------------------------------------------ //
  //  health + token
  // ------------------------------------------------------------------ //
  async function pollHealth() {
    try {
      const h = await api("/api/health");
      $("#health-dot").style.background = "#34d399";
      $("#health-text").innerHTML = `<span class="text-[#6ee7b7]">${esc(h.status)}</span> · <span class="mono text-[var(--text-mute)]">v${esc(h.version)}</span>`;
    } catch (e) {
      $("#health-dot").style.background = "#ef4444";
      $("#health-text").textContent = e.status === 401 ? "auth required — set token" : "offline";
    }
  }

  function setupToken() {
    const pop = $("#token-pop"), input = $("#token-input"), state = $("#token-state");
    const refresh = () => {
      const has = !!getToken();
      state.textContent = has ? "Token ✓" : "Token";
      input.value = getToken();
    };
    refresh();
    $("#token-btn").addEventListener("click", (e) => { e.stopPropagation(); pop.classList.toggle("hidden"); });
    document.addEventListener("click", (e) => { if (!pop.contains(e.target) && e.target.id !== "token-btn") pop.classList.add("hidden"); });
    $("#token-save").addEventListener("click", () => {
      const v = input.value.trim();
      if (v) localStorage.setItem(TOKEN_KEY, v); else localStorage.removeItem(TOKEN_KEY);
      refresh(); pop.classList.add("hidden");
      toast("Token saved", "ok");
      pollHealth(); go(current);
    });
    $("#token-clear").addEventListener("click", () => {
      localStorage.removeItem(TOKEN_KEY); refresh();
      toast("Token cleared", "ok"); pollHealth();
    });
  }

  // ------------------------------------------------------------------ //
  //  icons
  // ------------------------------------------------------------------ //
  function svg(p) { return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" width="18" height="18">${p}</svg>`; }
  function icoGrid() { return svg(`<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>`); }
  function icoServer() { return svg(`<rect x="3" y="4" width="18" height="6" rx="2"/><rect x="3" y="14" width="18" height="6" rx="2"/><path d="M7 7h.01M7 17h.01"/>`); }
  function icoCheck() { return svg(`<path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>`); }
  function icoList() { return svg(`<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>`); }
  function icoShield() { return svg(`<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/>`); }
  function icoRadar() { return svg(`<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><path d="M12 12l6-3"/><circle cx="12" cy="12" r="1" fill="currentColor"/>`); }

  // ------------------------------------------------------------------ //
  //  boot
  // ------------------------------------------------------------------ //
  buildNav();
  setupToken();
  pollHealth();
  setInterval(pollHealth, 15000);

  $("#refresh-btn").addEventListener("click", () => { go(current); pollHealth(); });
  window.addEventListener("hashchange", () => {
    const k = location.hash.replace("#", "");
    if (VIEWS[k] && k !== current) go(k);
  });

  const initial = location.hash.replace("#", "");
  go(VIEWS[initial] ? initial : "overview");
})();
