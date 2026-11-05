/* SOVEREIGN-WATCH // OSINT Analyst Workbench Client Engine */
(function () {
  "use strict";

  const TIER_COLORS = {
    CRITICAL: "#ef4444",
    HIGH: "#f97316",
    ELEVATED: "#eab308",
    GUARDED: "#38bdf8",
    LOW: "#10b981",
    UNRATED: "#64748b",
  };

  const ARCHETYPE_COLORS = {
    "Acute Crisis & Coercive Regimes": "#ef4444",
    "Capital-Locked & Monetary Stress States": "#f97316",
    "State-Directed / Illiberal Market Hubs": "#a855f7",
    "Hybrid Institutional / Transitional States": "#eab308",
    "Resilient Rule-of-Law Economies": "#10b981",
  };

  const PLOTLY_BASE_LAYOUT = {
    paper_bgcolor: "rgba(0,0,0,0)",
    plot_bgcolor: "rgba(15,22,34,0.6)",
    font: { family: "Inter, -apple-system, sans-serif", color: "#cbd5e1", size: 11.5 },
    margin: { l: 48, r: 22, t: 18, b: 42 },
  };

  const PLOTLY_CONFIG = {
    responsive: true,
    displaylogo: false,
    modeBarButtonsToRemove: ["lasso2d", "select2d"],
  };

  const state = {
    overview: null,
    latestWatchlist: [], // Full 165-country dataset for latest year
    mapData: [],         // Watchlist dataset for selected map year
    filteredWatchlist: [],
    sortCol: "composite_risk_score",
    sortAsc: false,
    currentDossierIso: "VEN",
    currentDossierPayload: null,
  };

  // --- Utilities ---
  function fmt(v, d = 2) {
    if (v === null || v === undefined || Number.isNaN(Number(v))) return "—";
    return Number(v).toFixed(d);
  }

  function fmtDelta(v, d = 2) {
    if (v === null || v === undefined || Number.isNaN(Number(v))) return '<span class="delta-flat">—</span>';
    const num = Number(v);
    const sign = num > 0 ? "+" : "";
    const cls = num <= -0.25 ? "delta-neg" : num >= 0.2 ? "delta-pos" : "delta-flat";
    return `<span class="${cls}">${sign}${num.toFixed(d)}</span>`;
  }

  function esc(str) {
    if (str === null || str === undefined) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  async function apiGet(url) {
    const resp = await fetch(url);
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({ error: resp.statusText }));
      throw new Error(err.error || `HTTP ${resp.status}`);
    }
    return resp.json();
  }

  // --- Tab Switching ---
  function switchTab(tabId) {
    document.querySelectorAll(".tab-btn").forEach((btn) => {
      btn.classList.toggle("active", btn.dataset.tab === tabId);
    });
    document.querySelectorAll(".tab-panel").forEach((panel) => {
      panel.classList.toggle("active", panel.id === tabId);
    });
    // Resize Plotly charts inside newly visible tab
    setTimeout(() => {
      document.querySelectorAll(`#${tabId} .js-plotly-plot`).forEach((el) => {
        window.Plotly.Plots.resize(el);
      });
    }, 40);
  }

  function openCountryDossier(isoOrName) {
    if (!isoOrName) return;
    switchTab("tab-dossier");
    loadDossier(isoOrName);
  }

  // --- Initialization ---
  async function init() {
    bindEvents();

    const [overview, wlResp] = await Promise.all([
      apiGet("/api/overview"),
      apiGet("/api/watchlist"),
    ]);

    state.overview = overview;
    state.latestWatchlist = wlResp.items || [];
    state.mapData = state.latestWatchlist;

    renderOverviewKPIs(overview);
    populateSelectors(overview, state.latestWatchlist);
    renderRegionalCards(overview.regional_summary || []);
    renderWorldMap();
    renderShockScatter();
    applyWatchlistFiltersAndRender();

    // Populate Tab 2 sidebars & feed
    renderDecayBarChart(overview.fastest_decay || []);
    renderReformersList(overview.fastest_reform || []);
    await loadAlertsFeed();

    // Preload initial Dossier + Tab 4 Lab + Provenance Vault
    await loadDossier(state.currentDossierIso);
    renderCorrelationLab();
    renderPcaClusters();
    await loadProvenanceVault();
  }

  function bindEvents() {
    document.querySelectorAll(".tab-btn").forEach((btn) => {
      btn.addEventListener("click", () => switchTab(btn.dataset.tab));
    });

    document.getElementById("provenanceBadge").addEventListener("click", () => {
      switchTab("tab-fusion");
    });

    // Global Quick Jump
    const jumpInput = document.getElementById("quickJumpInput");
    document.getElementById("quickJumpBtn").addEventListener("click", () => {
      const val = jumpInput.value.trim();
      if (!val) return;
      const iso = val.split("—")[0].trim();
      openCountryDossier(iso);
    });
    jumpInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        const val = jumpInput.value.trim();
        if (val) openCountryDossier(val.split("—")[0].trim());
      }
    });

    // Map controls
    document.getElementById("mapMetricSelect").addEventListener("change", renderWorldMap);
    document.getElementById("mapYearSelect").addEventListener("change", async (e) => {
      const yr = e.target.value;
      const resp = await apiGet(`/api/watchlist?year=${encodeURIComponent(yr)}`);
      state.mapData = resp.items || [];
      renderWorldMap();
    });

    // Watchlist filters & sorting
    ["wlSearch", "wlRegionFilter", "wlTierFilter", "wlArchetypeFilter"].forEach((id) => {
      const el = document.getElementById(id);
      el.addEventListener(el.tagName === "INPUT" ? "input" : "change", applyWatchlistFiltersAndRender);
    });

    document.querySelectorAll("#watchlistTable thead th[data-sort]").forEach((th) => {
      th.addEventListener("click", () => {
        const col = th.dataset.sort;
        if (state.sortCol === col) {
          state.sortAsc = !state.sortAsc;
        } else {
          state.sortCol = col;
          state.sortAsc = col === "risk_rank" || col === "iso_code" || col === "country_name";
        }
        applyWatchlistFiltersAndRender();
      });
    });

    // Alerts filters
    ["alertSearch", "alertYearFilter", "alertSevFilter", "alertTypeFilter"].forEach((id) => {
      const el = document.getElementById(id);
      el.addEventListener(el.tagName === "INPUT" ? "input" : "change", loadAlertsFeed);
    });

    // Dossier controls
    document.getElementById("dossierCountrySelect").addEventListener("change", (e) => {
      loadDossier(e.target.value);
    });
    document.querySelectorAll(".chip-btn").forEach((chip) => {
      chip.addEventListener("click", () => loadDossier(chip.dataset.iso));
    });
    document.getElementById("downloadJsonBtn").addEventListener("click", () => {
      if (!state.currentDossierPayload) return;
      const blob = new Blob([JSON.stringify(state.currentDossierPayload, null, 2)], {
        type: "application/json",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `OSINT_Dossier_${state.currentDossierPayload.iso_code}_${state.currentDossierPayload.latest_year}.json`;
      a.click();
      URL.revokeObjectURL(url);
    });

    // Correlation Lab controls
    document.getElementById("corrXSelect").addEventListener("change", renderCorrelationLab);
    document.getElementById("corrYSelect").addEventListener("change", renderCorrelationLab);

    // Re-audit SHA-256 button
    document.getElementById("reverifyBtn").addEventListener("click", loadProvenanceVault);
  }

  // --- Overview & Selectors ---
  function renderOverviewKPIs(ov) {
    document.getElementById("kpiTotalCountries").textContent = ov.jurisdictions_monitored;
    document.getElementById("kpiCycleMeta").textContent = `1950–${ov.latest_year} Longitudinal Store`;

    const tc = ov.tier_counts || {};
    document.getElementById("kpiCritHigh").textContent = ov.critical_and_high_count;
    document.getElementById("kpiTierBreakdown").textContent =
      `${tc.CRITICAL || 0} Critical · ${tc.HIGH || 0} High · ${tc.ELEVATED || 0} Elevated`;

    document.getElementById("kpiActiveAlerts").textContent = ov.active_alerts_count;
    document.getElementById("kpiCritAlertsMeta").textContent =
      `${ov.critical_alerts_count} Critical triggers in ${ov.latest_year}`;
    document.getElementById("navAlertBadge").textContent = ov.active_alerts_count;

    const fd = (ov.fastest_decay || [])[0];
    if (fd) {
      document.getElementById("kpiFastestDecay").textContent =
        `${fd.iso_code} (${fd.delta_5y > 0 ? "+" : ""}${fmt(fd.delta_5y, 2)})`;
      document.getElementById("kpiFastestDecayMeta").textContent =
        `${fd.country_name} · Z=${fmt(fd.z_velocity_5y, 2)}σ`;
    }

    const ps = ov.provenance_status || {};
    const xv = ps.cross_verification || {};
    document.getElementById("kpiProvStatus").textContent = ps.overall_status || "PASS";
    document.getElementById("kpiProvMeta").textContent =
      `${ps.artifact_count || 0} SHA-256 files · ${xv.agreement_pct || 100}% API Match`;
  }

  function populateSelectors(ov, items) {
    // Map years
    const mapYr = document.getElementById("mapYearSelect");
    mapYr.innerHTML = (ov.available_years || [])
      .map((y) => `<option value="${y}">${y}</option>`)
      .join("");

    // Alert years
    const alYr = document.getElementById("alertYearFilter");
    const recentYrs = (ov.available_years || []).slice(0, 4);
    alYr.innerHTML =
      recentYrs.map((y, idx) => `<option value="${y}" ${idx === 0 ? "selected" : ""}>Cycle ${y}</option>`).join("") +
      `<option value="ALL">All Recent Cycles</option>`;

    // Regions
    const regions = Array.from(new Set(items.map((d) => d.wb_region || "Unclassified"))).sort();
    document.getElementById("wlRegionFilter").innerHTML =
      `<option value="ALL">All Regions</option>` +
      regions.map((r) => `<option value="${esc(r)}">${esc(r)}</option>`).join("");

    // Archetypes
    const archs = Array.from(new Set(items.map((d) => d.regime_archetype).filter(Boolean))).sort();
    document.getElementById("wlArchetypeFilter").innerHTML =
      `<option value="ALL">All ML Archetypes</option>` +
      archs.map((a) => `<option value="${esc(a)}">${esc(a)}</option>`).join("");

    // Country datalist & Dossier select
    const sortedByName = [...items].sort((a, b) => a.country_name.localeCompare(b.country_name));
    document.getElementById("countryDatalist").innerHTML = sortedByName
      .map((c) => `<option value="${c.iso_code} — ${esc(c.country_name)}"></option>`)
      .join("");

    document.getElementById("dossierCountrySelect").innerHTML = sortedByName
      .map(
        (c) =>
          `<option value="${c.iso_code}" ${c.iso_code === state.currentDossierIso ? "selected" : ""}>` +
          `${esc(c.country_name)} (${c.iso_code}) — Risk ${fmt(c.composite_risk_score, 1)} [${c.threat_tier}]</option>`
      )
      .join("");
  }

  function renderRegionalCards(regList) {
    const grid = document.getElementById("regionalCardsGrid");
    grid.innerHTML = regList
      .map((r) => {
        const d5 = r.avg_delta_5y;
        return `
          <div class="reg-card" data-region="${esc(r.wb_region)}">
            <div class="reg-name">${esc(r.wb_region)}</div>
            <div class="reg-metrics">
              <span>Avg Risk: <strong>${fmt(r.avg_risk, 1)}</strong></span>
              <span>Crit/High: <strong style="color:#f97316">${r.high_crit_count}/${r.countries}</strong></span>
            </div>
            <div class="reg-metrics" style="margin-top:4px;">
              <span>EFW: ${fmt(r.avg_efw, 2)}</span>
              <span>5Y Drift: ${fmtDelta(d5, 2)}</span>
            </div>
          </div>
        `;
      })
      .join("");

    grid.querySelectorAll(".reg-card").forEach((card) => {
      card.addEventListener("click", () => {
        document.getElementById("wlRegionFilter").value = card.dataset.region;
        applyWatchlistFiltersAndRender();
        document.getElementById("watchlistTable").scrollIntoView({ behavior: "smooth" });
      });
    });
  }

  // --- World Choropleth Map ---
  function renderWorldMap() {
    const metric = document.getElementById("mapMetricSelect").value;
    const rows = state.mapData.filter((d) => d[metric] !== null && d[metric] !== undefined);

    const isGoodHigh = metric === "efw_score" || metric === "delta_5y";
    const colorscale =
      metric === "delta_5y"
        ? [
            [0.0, "#dc2626"],
            [0.35, "#f97316"],
            [0.55, "#334155"],
            [0.8, "#38bdf8"],
            [1.0, "#10b981"],
          ]
        : isGoodHigh
        ? [
            [0.0, "#dc2626"],
            [0.35, "#f97316"],
            [0.6, "#eab308"],
            [0.8, "#38bdf8"],
            [1.0, "#10b981"],
          ]
        : [
            [0.0, "#0f766e"],
            [0.3, "#0284c7"],
            [0.52, "#eab308"],
            [0.72, "#f97316"],
            [1.0, "#dc2626"],
          ];

    const trace = {
      type: "choropleth",
      locationmode: "ISO-3",
      locations: rows.map((d) => d.iso_code),
      z: rows.map((d) => d[metric]),
      text: rows.map(
        (d) =>
          `<b>${d.country_name} (${d.iso_code})</b><br>` +
          `Threat Tier: ${d.threat_tier} (Risk: ${fmt(d.composite_risk_score, 1)})<br>` +
          `EFOTW Score: ${fmt(d.efw_score, 2)} (Rank #${d.efw_rank || "—"})<br>` +
          `5Y Panel Δ: ${d.delta_5y !== null ? (d.delta_5y > 0 ? "+" : "") + fmt(d.delta_5y, 2) : "—"}`
      ),
      hoverinfo: "text",
      colorscale: colorscale,
      zmid: metric === "delta_5y" ? 0 : undefined,
      marker: { line: { color: "#0b1018", width: 0.5 } },
      colorbar: {
        thickness: 11,
        len: 0.78,
        tickfont: { color: "#94a3b8", size: 10 },
      },
    };

    const layout = {
      ...PLOTLY_BASE_LAYOUT,
      margin: { l: 0, r: 0, t: 4, b: 0 },
      geo: {
        bgcolor: "rgba(0,0,0,0)",
        showframe: false,
        showcoastlines: false,
        projection: { type: "natural earth" },
        landcolor: "#162032",
        oceancolor: "#090d14",
        showocean: true,
        lakecolor: "#090d14",
      },
    };

    const el = document.getElementById("worldMapChart");
    window.Plotly.react(el, [trace], layout, PLOTLY_CONFIG);

    el.removeAllListeners && el.removeAllListeners("plotly_click");
    el.on("plotly_click", (ev) => {
      if (ev.points && ev.points[0] && ev.points[0].location) {
        openCountryDossier(ev.points[0].location);
      }
    });
  }

  // --- 5Y Regime Shock Scatter ---
  function renderShockScatter() {
    const valid = state.latestWatchlist.filter(
      (d) => d.efw_score !== null && d.delta_5y !== null
    );
    const tiers = ["CRITICAL", "HIGH", "ELEVATED", "GUARDED", "LOW"];
    const traces = tiers.map((tier) => {
      const grp = valid.filter((d) => d.threat_tier === tier);
      return {
        type: "scatter",
        mode: "markers+text",
        name: tier,
        x: grp.map((d) => d.efw_score),
        y: grp.map((d) => d.delta_5y),
        customdata: grp.map((d) => d.iso_code),
        text: grp.map((d) =>
          d.delta_5y <= -0.55 || d.composite_risk_score >= 60 ? d.iso_code : ""
        ),
        textposition: "top center",
        textfont: { size: 9.5, color: "#e2e8f0" },
        hovertemplate: grp.map(
          (d) =>
            `<b>${d.country_name} (${d.iso_code})</b><br>` +
            `EFW Score: ${fmt(d.efw_score, 2)}<br>` +
            `5Y Panel Velocity: ${d.delta_5y > 0 ? "+" : ""}${fmt(d.delta_5y, 3)}<br>` +
            `Composite Risk: ${fmt(d.composite_risk_score, 1)}<extra></extra>`
        ),
        marker: {
          color: TIER_COLORS[tier],
          size: grp.map((d) => Math.max(7, (d.composite_risk_score || 30) * 0.25)),
          opacity: 0.85,
          line: { width: 0.8, color: "#080c12" },
        },
      };
    });

    const layout = {
      ...PLOTLY_BASE_LAYOUT,
      xaxis: {
        title: "2024 EFOTW Headline Score (0–10)",
        gridcolor: "#1a2639",
        zeroline: false,
      },
      yaxis: {
        title: "5-Year Panel Velocity (Δ5Y, 2019→2024)",
        gridcolor: "#1a2639",
        zeroline: true,
        zerolinecolor: "#475569",
        zerolinewidth: 1.2,
      },
      legend: { orientation: "h", y: 1.11, x: 0, font: { size: 10 } },
      shapes: [
        {
          type: "line",
          x0: 2.5,
          x1: 9.0,
          y0: -0.5,
          y1: -0.5,
          line: { color: "rgba(239,68,68,0.45)", width: 1, dash: "dot" },
        },
      ],
    };

    const el = document.getElementById("shockScatterChart");
    window.Plotly.react(el, traces, layout, PLOTLY_CONFIG);
    el.removeAllListeners && el.removeAllListeners("plotly_click");
    el.on("plotly_click", (ev) => {
      const iso = ev.points && ev.points[0] && ev.points[0].customdata;
      if (iso) openCountryDossier(iso);
    });
  }

  // --- Watchlist Table ---
  function applyWatchlistFiltersAndRender() {
    const q = document.getElementById("wlSearch").value.trim().toLowerCase();
    const reg = document.getElementById("wlRegionFilter").value;
    const tier = document.getElementById("wlTierFilter").value;
    const arch = document.getElementById("wlArchetypeFilter").value;

    let rows = state.latestWatchlist.filter((d) => {
      if (reg !== "ALL" && (d.wb_region || "Unclassified") !== reg) return false;
      if (tier !== "ALL" && d.threat_tier !== tier) return false;
      if (arch !== "ALL" && d.regime_archetype !== arch) return false;
      if (
        q &&
        !d.country_name.toLowerCase().includes(q) &&
        !d.iso_code.toLowerCase().includes(q)
      ) {
        return false;
      }
      return true;
    });

    const col = state.sortCol;
    const dir = state.sortAsc ? 1 : -1;
    rows.sort((a, b) => {
      const va = a[col];
      const vb = b[col];
      if (va === null || va === undefined) return 1;
      if (vb === null || vb === undefined) return -1;
      if (typeof va === "string") return va.localeCompare(vb) * dir;
      return (va - vb) * dir;
    });

    state.filteredWatchlist = rows;
    document.getElementById("watchlistCount").textContent = rows.length;

    const tbody = document.getElementById("watchlistBody");
    tbody.innerHTML = rows
      .map(
        (r) => `
        <tr class="clickable-row" data-iso="${r.iso_code}">
          <td class="num">${r.risk_rank || "—"}</td>
          <td><span class="iso-pill">${r.iso_code}</span></td>
          <td><strong>${esc(r.country_name)}</strong></td>
          <td><span class="tier-badge tier-${r.threat_tier}">${r.threat_tier}</span></td>
          <td class="num"><strong>${fmt(r.composite_risk_score, 1)}</strong></td>
          <td class="num">${fmt(r.efw_score, 2)}</td>
          <td class="num">${fmtDelta(r.delta_5y, 2)}</td>
          <td class="num">${fmt(r.inst_decay_risk, 1)}</td>
          <td class="num">${fmt(r.monetary_stress_risk, 1)}</td>
          <td class="num">${fmt(r.capital_siege_risk, 1)}</td>
          <td class="num">${fmt(r.state_coercion_risk, 1)}</td>
          <td class="num">${fmt(r.wgi_political_stability, 1)}</td>
          <td class="num">${
            r.alert_count > 0
              ? `<span class="tier-badge tier-CRITICAL">${r.alert_count}</span>`
              : '<span class="delta-flat">0</span>'
          }</td>
          <td style="font-size:11.5px;color:#94a3b8;">${esc(r.regime_archetype)}</td>
        </tr>
      `
      )
      .join("");

    tbody.querySelectorAll("tr.clickable-row").forEach((tr) => {
      tr.addEventListener("click", () => openCountryDossier(tr.dataset.iso));
    });
  }

  // --- Tab 2: Early-Warning Alerts ---
  async function loadAlertsFeed() {
    const yr = document.getElementById("alertYearFilter").value || "2024";
    const sev = document.getElementById("alertSevFilter").value;
    const atype = document.getElementById("alertTypeFilter").value;
    const q = document.getElementById("alertSearch").value.trim();

    const params = new URLSearchParams({
      year: yr,
      severity: sev,
      alert_type: atype,
      q: q,
    });
    const resp = await apiGet(`/api/alerts?${params.toString()}`);
    const items = resp.items || [];
    document.getElementById("alertFeedCount").textContent = items.length;

    const container = document.getElementById("alertsContainer");
    if (!items.length) {
      container.innerHTML = `<div class="corr-stats-bar">No early-warning triggers match the selected filters.</div>`;
      return;
    }

    container.innerHTML = items
      .map((a) => {
        const metrics = a.trigger_metrics || {};
        const chips = Object.entries(metrics)
          .map(([k, v]) => `<span class="metric-chip">${esc(k)}: ${esc(v)}</span>`)
          .join("");
        return `
          <div class="alert-card sev-${a.severity}">
            <div class="alert-top">
              <div class="alert-meta-left">
                <span class="tier-badge tier-${a.severity}">${a.severity}</span>
                <span class="iso-pill">${a.iso_code}</span>
                <span class="alert-type-tag">${esc(a.alert_type)}</span>
                <span class="alert-type-tag">${a.year} · ${esc(a.wb_region)}</span>
              </div>
              <button class="btn btn-outline alert-dossier-btn" data-iso="${a.iso_code}" style="padding:3px 9px;font-size:11px;">
                Dossier →
              </button>
            </div>
            <div class="alert-headline">${esc(a.headline)}</div>
            <div class="alert-evidence">${esc(a.evidence_summary)}</div>
            <div class="alert-chips">${chips}</div>
          </div>
        `;
      })
      .join("");

    container.querySelectorAll(".alert-dossier-btn").forEach((btn) => {
      btn.addEventListener("click", () => openCountryDossier(btn.dataset.iso));
    });
  }

  function renderDecayBarChart(decayRows) {
    const top = [...decayRows].slice(0, 12).reverse();
    const trace = {
      type: "bar",
      orientation: "h",
      y: top.map((r) => `${r.country_name} (${r.iso_code})`),
      x: top.map((r) => r.delta_5y),
      customdata: top.map((r) => r.iso_code),
      text: top.map((r) => `${fmt(r.delta_5y, 2)} (${fmt(r.z_velocity_5y, 1)}σ)`),
      textposition: "auto",
      marker: {
        color: top.map((r) => TIER_COLORS[r.threat_tier] || "#ef4444"),
      },
      hovertemplate: "<b>%{y}</b><br>5Y Panel Δ: %{x:.3f}<extra></extra>",
    };
    const layout = {
      ...PLOTLY_BASE_LAYOUT,
      margin: { l: 155, r: 18, t: 8, b: 36 },
      xaxis: { title: "5-Year Panel Score Shift (2019 → 2024)", gridcolor: "#1a2639" },
      yaxis: { automargin: true },
    };
    const el = document.getElementById("decayBarChart");
    window.Plotly.react(el, [trace], layout, PLOTLY_CONFIG);
    el.removeAllListeners && el.removeAllListeners("plotly_click");
    el.on("plotly_click", (ev) => {
      const iso = ev.points && ev.points[0] && ev.points[0].customdata;
      if (iso) openCountryDossier(iso);
    });
  }

  function renderReformersList(reformRows) {
    const box = document.getElementById("reformersList");
    box.innerHTML = reformRows
      .slice(0, 8)
      .map(
        (r) => `
        <div class="reformer-row" data-iso="${r.iso_code}">
          <div>
            <span class="iso-pill">${r.iso_code}</span>
            <strong style="margin-left:6px;">${esc(r.country_name)}</strong>
            <span style="font-size:11px;color:#94a3b8;margin-left:6px;">EFW ${fmt(r.efw_score, 2)}</span>
          </div>
          <div style="font-family:var(--font-mono);font-size:12px;">
            ${fmtDelta(r.delta_5y, 2)}
          </div>
        </div>
      `
      )
      .join("");
    box.querySelectorAll(".reformer-row").forEach((row) => {
      row.addEventListener("click", () => openCountryDossier(row.dataset.iso));
    });
  }

  // --- Tab 3: Country Intelligence Dossier ---
  async function loadDossier(isoOrName) {
    try {
      const payload = await apiGet(`/api/country/${encodeURIComponent(isoOrName)}`);
      state.currentDossierIso = payload.iso_code;
      state.currentDossierPayload = payload;

      const sel = document.getElementById("dossierCountrySelect");
      if (sel) sel.value = payload.iso_code;

      const dlMd = document.getElementById("downloadMdBtn");
      dlMd.href = `/api/dossier/${encodeURIComponent(payload.iso_code)}.md`;

      renderDossierBanner(payload);
      renderDossierTimeline(payload);
      renderDossierRadar(payload);
      renderDossierSubIndicators(payload.sub_indicators || []);
      renderDossierWgi(payload.summary || {});
      renderDossierAlerts(payload.alerts || []);
    } catch (err) {
      console.error("Failed to load dossier:", err);
    }
  }

  function renderDossierBanner(p) {
    const s = p.summary || {};
    const rb = p.regional_benchmark || {};
    document.getElementById("dossierBanner").innerHTML = `
      <div class="dossier-banner-grid">
        <div>
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">
            <span class="iso-pill">${p.iso_code}</span>
            <span class="tier-badge tier-${s.threat_tier}">${s.threat_tier} THREAT TIER</span>
          </div>
          <h2 style="font-size:20px;font-weight:700;color:#f8fafc;">${esc(p.country_name)}</h2>
          <p style="font-size:12px;color:#94a3b8;margin-top:2px;">
            ${esc(s.wb_region || "Global")} · ${esc(s.wb_income_group || "Unclassified")} ·
            Archetype: <strong style="color:#e2e8f0">${esc(s.regime_archetype)}</strong>
          </p>
        </div>

        <div class="dossier-stat-box">
          <span class="kpi-label">COMPOSITE SOVEREIGN RISK</span>
          <div class="kpi-value" style="color:${TIER_COLORS[s.threat_tier] || "#f8fafc"}">
            ${fmt(s.composite_risk_score, 1)} <span style="font-size:12px;color:#94a3b8">/ 100</span>
          </div>
          <span class="kpi-meta">Global Risk Rank #${s.risk_rank || "—"} · Reg Avg ${fmt(rb.avg_composite_risk, 1)}</span>
        </div>

        <div class="dossier-stat-box">
          <span class="kpi-label">EFOTW HEADLINE SCORE</span>
          <div class="kpi-value">${fmt(s.efw_score, 2)} <span style="font-size:12px;color:#94a3b8">/ 10</span></div>
          <span class="kpi-meta">Freedom Rank #${s.efw_rank || "—"} (Quartile ${s.efw_quartile || "—"})</span>
        </div>

        <div class="dossier-stat-box">
          <span class="kpi-label">5-YEAR PANEL VELOCITY</span>
          <div class="kpi-value">${fmtDelta(s.delta_5y, 3)}</div>
          <span class="kpi-meta">Z-Score: ${fmt(s.z_velocity_5y, 2)}σ · 10Y Δ: ${fmt(s.delta_10y, 2)}</span>
        </div>

        <div class="dossier-stat-box">
          <span class="kpi-label">CROSS-SOURCE ASYMMETRY</span>
          <div class="kpi-value">${fmt(s.cross_source_gap, 1)} <span style="font-size:12px;color:#94a3b8">pts</span></div>
          <span class="kpi-meta">EFW Pct (${fmt(s.efw_percentile, 0)}%) vs WGI Civic/Stab</span>
        </div>
      </div>
    `;
  }

  function renderDossierTimeline(p) {
    const tl = p.timeline || [];
    const years = tl.map((d) => d.year);

    const traces = [
      {
        type: "scatter",
        mode: "lines+markers",
        name: "Time-Consistent Panel EFW (1970–2024)",
        x: years,
        y: tl.map((d) => d.panel_efw_score),
        connectgaps: true,
        line: { color: "#38bdf8", width: 2.6 },
        marker: { size: 5 },
      },
      {
        type: "scatter",
        mode: "lines+markers",
        name: "Headline EFW Rating",
        x: years,
        y: tl.map((d) => d.efw_score),
        connectgaps: true,
        line: { color: "#10b981", width: 1.6, dash: "dot" },
        marker: { size: 4 },
      },
      {
        type: "scatter",
        mode: "lines",
        name: "Regional Peer Avg (Panel)",
        x: years,
        y: tl.map((d) => d.regional_panel_avg),
        connectgaps: true,
        line: { color: "#94a3b8", width: 1.5, dash: "dash" },
      },
    ];

    if (tl.some((d) => d.hist_efw_score !== null && d.hist_efw_score !== undefined)) {
      traces.push({
        type: "scatter",
        mode: "lines+markers",
        name: "Historical EFW (1950–1965)",
        x: years,
        y: tl.map((d) => d.hist_efw_score),
        connectgaps: true,
        line: { color: "#eab308", width: 2.2 },
        marker: { size: 6, symbol: "diamond" },
      });
    }

    const layout = {
      ...PLOTLY_BASE_LAYOUT,
      xaxis: { title: "Year", gridcolor: "#1a2639" },
      yaxis: { title: "Economic Freedom Rating (0–10)", range: [0, 10], gridcolor: "#1a2639" },
      legend: { orientation: "h", y: 1.13, x: 0, font: { size: 10.5 } },
    };

    window.Plotly.react(
      document.getElementById("dossierTimelineChart"),
      traces,
      layout,
      PLOTLY_CONFIG
    );
  }

  function renderDossierRadar(p) {
    const s = p.summary || {};
    const rb = p.regional_benchmark || {};
    const cats = [
      "Institutional Decay",
      "Monetary Stress",
      "Capital Siege",
      "Regime Velocity Shock",
      "State Coercion",
      "Institutional Decay",
    ];
    const jurVals = [
      s.inst_decay_risk || 0,
      s.monetary_stress_risk || 0,
      s.capital_siege_risk || 0,
      s.regime_shock_risk || 0,
      s.state_coercion_risk || 0,
      s.inst_decay_risk || 0,
    ];
    const regVals = [
      rb.avg_inst_decay || 0,
      rb.avg_monetary_stress || 0,
      rb.avg_capital_siege || 0,
      rb.avg_regime_shock || 0,
      rb.avg_state_coercion || 0,
      rb.avg_inst_decay || 0,
    ];

    const traces = [
      {
        type: "scatterpolar",
        r: jurVals,
        theta: cats,
        fill: "toself",
        name: p.iso_code,
        fillcolor: "rgba(239, 68, 68, 0.24)",
        line: { color: "#ef4444", width: 2.2 },
      },
      {
        type: "scatterpolar",
        r: regVals,
        theta: cats,
        fill: "toself",
        name: "Regional Peer Avg",
        fillcolor: "rgba(56, 189, 248, 0.12)",
        line: { color: "#38bdf8", width: 1.8, dash: "dot" },
      },
    ];

    const layout = {
      ...PLOTLY_BASE_LAYOUT,
      margin: { l: 42, r: 42, t: 28, b: 28 },
      polar: {
        bgcolor: "rgba(15,22,34,0.6)",
        radialaxis: {
          visible: true,
          range: [0, 100],
          gridcolor: "#1e2c42",
          tickfont: { size: 9, color: "#94a3b8" },
        },
        angularaxis: {
          gridcolor: "#1e2c42",
          tickfont: { size: 10.5, color: "#e2e8f0" },
        },
      },
      legend: { orientation: "h", y: 1.12, x: 0.15, font: { size: 10.5 } },
    };

    window.Plotly.react(
      document.getElementById("dossierRadarChart"),
      traces,
      layout,
      PLOTLY_CONFIG
    );
  }

  function renderDossierSubIndicators(subs) {
    const tbody = document.getElementById("dossierSubIndBody");
    tbody.innerHTML = subs
      .map((item) => {
        const vuln = item.vulnerability_100;
        const barColor =
          vuln === null
            ? "#475569"
            : vuln >= 65
            ? "#ef4444"
            : vuln >= 45
            ? "#f97316"
            : vuln >= 28
            ? "#eab308"
            : "#10b981";
        return `
          <tr>
            <td><strong>${esc(item.label)}</strong></td>
            <td style="color:#94a3b8;font-size:11.5px;">${esc(item.domain)}</td>
            <td class="num"><strong>${fmt(item.score_10, 2)}</strong></td>
            <td class="num">${fmtDelta(item.delta_5y, 2)}</td>
            <td>
              <div class="vuln-bar-wrap">
                <div class="vuln-bar-track">
                  <div class="vuln-bar-fill" style="width:${vuln !== null ? vuln : 0}%;background:${barColor};"></div>
                </div>
                <span style="font-family:var(--font-mono);font-size:11px;color:#cbd5e1;">${
                  vuln !== null ? fmt(vuln, 0) + "%" : "—"
                }</span>
              </div>
            </td>
          </tr>
        `;
      })
      .join("");
  }

  function renderDossierWgi(s) {
    const cards = [
      ["WGI Rule of Law (0–100)", fmt(s.wgi_rule_of_law, 1)],
      ["WGI Control of Corruption", fmt(s.wgi_control_corruption, 1)],
      ["WGI Political Stability", fmt(s.wgi_political_stability, 1)],
      ["WGI Voice & Accountability", fmt(s.wgi_voice_accountability, 1)],
      [
        "GDP per Capita PPP (2021 $)",
        s.wb_gdp_pcap_ppp ? "$" + Number(s.wb_gdp_pcap_ppp).toLocaleString(undefined, { maximumFractionDigits: 0 }) : "—",
      ],
      ["Headline CPI Inflation (WB)", s.wb_cpi_inflation !== null && s.wb_cpi_inflation !== undefined ? fmt(s.wb_cpi_inflation, 1) + "%" : "—"],
      ["Trade Openness (% GDP)", s.wb_trade_gdp ? fmt(s.wb_trade_gdp, 1) + "%" : "—"],
      ["Military Spend (% GDP)", s.wb_mil_exp_gdp ? fmt(s.wb_mil_exp_gdp, 2) + "%" : "—"],
    ];
    document.getElementById("dossierWgiGrid").innerHTML = cards
      .map(
        ([label, val]) => `
        <div class="wgi-card">
          <div class="wgi-card-label">${esc(label)}</div>
          <div class="wgi-card-val">${esc(val)}</div>
        </div>
      `
      )
      .join("");
  }

  function renderDossierAlerts(alerts) {
    const box = document.getElementById("dossierAlertsList");
    if (!alerts.length) {
      box.innerHTML = `<div class="corr-stats-bar">No early-warning anomalies triggered for this jurisdiction in 2021–2024.</div>`;
      return;
    }
    box.innerHTML = alerts
      .map(
        (a) => `
        <div class="alert-card sev-${a.severity}" style="padding:9px 11px;">
          <div class="alert-meta-left" style="margin-bottom:4px;">
            <span class="tier-badge tier-${a.severity}">${a.severity}</span>
            <span class="alert-type-tag">${a.year} · ${esc(a.alert_type)}</span>
          </div>
          <div style="font-size:12.5px;font-weight:600;color:#f8fafc;">${esc(a.headline)}</div>
          <div style="font-size:11.5px;color:#94a3b8;margin-top:3px;">${esc(a.evidence_summary)}</div>
        </div>
      `
      )
      .join("");
  }

  // --- Tab 4: Cross-Source Lab & PCA Clusters & Provenance ---
  function computeLinearStats(xs, ys) {
    const n = xs.length;
    if (n < 3) return { r: 0, slope: 0, intercept: 0 };
    const mx = xs.reduce((a, b) => a + b, 0) / n;
    const my = ys.reduce((a, b) => a + b, 0) / n;
    let cov = 0, vx = 0, vy = 0;
    for (let i = 0; i < n; i++) {
      const dx = xs[i] - mx;
      const dy = ys[i] - my;
      cov += dx * dy;
      vx += dx * dx;
      vy += dy * dy;
    }
    const r = vx > 0 && vy > 0 ? cov / Math.sqrt(vx * vy) : 0;
    const slope = vx > 0 ? cov / vx : 0;
    const intercept = my - slope * mx;
    return { r, slope, intercept };
  }

  function renderCorrelationLab() {
    const xSel = document.getElementById("corrXSelect");
    const ySel = document.getElementById("corrYSelect");
    const xKey = xSel.value;
    const yKey = ySel.value;
    const xLabel = xSel.options[xSel.selectedIndex].text;
    const yLabel = ySel.options[ySel.selectedIndex].text;

    const valid = state.latestWatchlist.filter(
      (d) => d[xKey] !== null && d[xKey] !== undefined && d[yKey] !== null && d[yKey] !== undefined
    );

    const xs = valid.map((d) => Number(d[xKey]));
    const ys = valid.map((d) => Number(d[yKey]));
    const { r, slope, intercept } = computeLinearStats(xs, ys);

    document.getElementById("corrStatsBanner").innerHTML =
      `Sample: <strong>N = ${valid.length}</strong> jurisdictions · ` +
      `Pearson Correlation: <strong style="color:#38bdf8">r = ${r >= 0 ? "+" : ""}${r.toFixed(3)}</strong> ` +
      `(R² = ${(r * r).toFixed(3)}) · Outliers far below/above OLS line flag cross-source divergence`;

    const tiers = ["CRITICAL", "HIGH", "ELEVATED", "GUARDED", "LOW"];
    const traces = tiers.map((tier) => {
      const grp = valid.filter((d) => d.threat_tier === tier);
      return {
        type: "scatter",
        mode: "markers+text",
        name: tier,
        x: grp.map((d) => d[xKey]),
        y: grp.map((d) => d[yKey]),
        customdata: grp.map((d) => d.iso_code),
        text: grp.map((d) => (Math.abs(d.cross_source_gap || 0) >= 34 ? d.iso_code : "")),
        textposition: "top center",
        textfont: { size: 9, color: "#cbd5e1" },
        marker: { color: TIER_COLORS[tier], size: 8.5, opacity: 0.86 },
        hovertemplate: grp.map(
          (d) =>
            `<b>${d.country_name} (${d.iso_code})</b><br>` +
            `${xLabel}: ${fmt(d[xKey], 2)}<br>` +
            `${yLabel}: ${fmt(d[yKey], 2)}<extra></extra>`
        ),
      };
    });

    if (xs.length >= 3) {
      const minX = Math.min(...xs);
      const maxX = Math.max(...xs);
      traces.push({
        type: "scatter",
        mode: "lines",
        name: "OLS Fit",
        x: [minX, maxX],
        y: [slope * minX + intercept, slope * maxX + intercept],
        line: { color: "#94a3b8", width: 1.5, dash: "dash" },
        hoverinfo: "skip",
      });
    }

    const layout = {
      ...PLOTLY_BASE_LAYOUT,
      xaxis: { title: xLabel, gridcolor: "#1a2639" },
      yaxis: { title: yLabel, gridcolor: "#1a2639" },
      legend: { orientation: "h", y: 1.12, x: 0, font: { size: 10 } },
    };

    const el = document.getElementById("corrScatterChart");
    window.Plotly.react(el, traces, layout, PLOTLY_CONFIG);
    el.removeAllListeners && el.removeAllListeners("plotly_click");
    el.on("plotly_click", (ev) => {
      const iso = ev.points && ev.points[0] && ev.points[0].customdata;
      if (iso) openCountryDossier(iso);
    });
  }

  function renderPcaClusters() {
    const valid = state.latestWatchlist.filter(
      (d) => d.pca_x !== null && d.pca_y !== null
    );
    const archetypes = Object.keys(ARCHETYPE_COLORS);
    const traces = archetypes.map((arch) => {
      const grp = valid.filter((d) => d.regime_archetype === arch);
      return {
        type: "scatter",
        mode: "markers+text",
        name: arch,
        x: grp.map((d) => d.pca_x),
        y: grp.map((d) => d.pca_y),
        customdata: grp.map((d) => d.iso_code),
        text: grp.map((d, i) => (i % 4 === 0 || d.composite_risk_score >= 60 ? d.iso_code : "")),
        textposition: "top center",
        textfont: { size: 9, color: "#cbd5e1" },
        marker: {
          color: ARCHETYPE_COLORS[arch] || "#38bdf8",
          size: 9,
          opacity: 0.88,
          line: { width: 0.7, color: "#080c12" },
        },
        hovertemplate: grp.map(
          (d) =>
            `<b>${d.country_name} (${d.iso_code})</b><br>` +
            `Archetype: ${d.regime_archetype}<br>` +
            `Composite Risk: ${fmt(d.composite_risk_score, 1)}<extra></extra>`
        ),
      };
    });

    const layout = {
      ...PLOTLY_BASE_LAYOUT,
      xaxis: { title: "Principal Component 1 (Overall Institutional & Sovereign Fragility)", gridcolor: "#1a2639" },
      yaxis: { title: "Principal Component 2 (Monetary Crisis vs. Illiberal Governance)", gridcolor: "#1a2639" },
      legend: { orientation: "h", y: 1.15, x: 0, font: { size: 9.8 } },
    };

    const el = document.getElementById("pcaClusterChart");
    window.Plotly.react(el, traces, layout, PLOTLY_CONFIG);
    el.removeAllListeners && el.removeAllListeners("plotly_click");
    el.on("plotly_click", (ev) => {
      const iso = ev.points && ev.points[0] && ev.points[0].customdata;
      if (iso) openCountryDossier(iso);
    });
  }

  async function loadProvenanceVault() {
    const audit = await apiGet("/api/provenance");
    const xv = audit.cross_verification || {};

    document.getElementById("crossVerBanner").innerHTML =
      `Chain-of-Custody Audit: <strong style="color:#10b981">${esc(audit.overall_status)}</strong> ` +
      `(Checked UTC: ${esc(audit.checked_at_utc)}) · ` +
      `SPA Internal API vs. Researcher Master XLSX Cross-Check: ` +
      `<strong style="color:#10b981">${xv.exact_matches || 0} / ${xv.countries_cross_checked || 0} Jurisdictions (${xv.agreement_pct || 0}% Exact Agreement)</strong>`;

    const tbody = document.getElementById("provenanceTableBody");
    tbody.innerHTML = (audit.artifacts || [])
      .map(
        (a) => `
        <tr>
          <td><strong>${esc(a.artifact_id)}</strong></td>
          <td><span class="tier-badge tier-LOW">${esc(a.status)}</span></td>
          <td style="font-size:11.5px;color:#94a3b8;max-width:340px;overflow:hidden;text-overflow:ellipsis;">${esc(a.source_url)}</td>
          <td style="font-family:var(--font-mono);font-size:11px;">${esc(a.local_path)}</td>
          <td><code class="hash-code">${esc(a.actual_sha256)}</code></td>
          <td class="num">${((a.size_bytes || 0) / 1024).toFixed(1)} KB</td>
          <td class="num">${a.record_count !== null && a.record_count !== undefined ? a.record_count : "—"}</td>
          <td style="font-family:var(--font-mono);font-size:11px;color:#94a3b8;">${esc(a.retrieved_at_utc)}</td>
        </tr>
      `
      )
      .join("");
  }

  document.addEventListener("DOMContentLoaded", init);
})();
