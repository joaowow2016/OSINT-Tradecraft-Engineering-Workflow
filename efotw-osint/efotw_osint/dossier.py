"""
Automated OSINT Country Intelligence Dossier & Global Threat SITREP Generator.
Produces structured JSON payloads (for Web API) and analyst-grade Markdown reports.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .config import DB_PATH, INDICATOR_LABELS, REPORTS_DIR
from .database import get_connection
from .provenance import ProvenanceLedger, utc_now_iso


def _row_to_dict(row: Any) -> dict[str, Any]:
    return dict(row) if row is not None else {}


def build_country_dossier_payload(
    iso_or_name: str,
    db_path: Path = DB_PATH,
) -> dict[str, Any]:
    """
    Assemble complete multi-source OSINT Country Intelligence Profile for a jurisdiction:
      - Latest Threat Assessment, 5 Threat Vectors, Regime Archetype & Regional Benchmark
      - Full Longitudinal Trajectory (1950-1965 historical + 1970-2024 Panel & Headline EFW)
      - 21 Granular Sub-Indicators with 5-Year Shifts & Vulnerability Ratings
      - World Bank / WGI Cross-Verification Metrics
      - Active & Historical Early-Warning Alerts
    """
    query_str = iso_or_name.strip()
    conn = get_connection(db_path)
    try:
        # Resolve ISO-3 or partial country name
        cur = conn.execute(
            """
            SELECT DISTINCT iso_code, country_name
            FROM sovereign_risk_scores
            WHERE UPPER(iso_code) = UPPER(?)
               OR LOWER(country_name) = LOWER(?)
               OR LOWER(country_name) LIKE LOWER(?)
            ORDER BY CASE WHEN UPPER(iso_code) = UPPER(?) THEN 0 ELSE 1 END, country_name
            LIMIT 1
            """,
            (query_str, query_str, f"%{query_str}%", query_str),
        )
        match = cur.fetchone()
        if not match:
            raise ValueError(f"Jurisdiction '{iso_or_name}' not found in SOVEREIGN-WATCH store.")
        iso = match["iso_code"]

        # Latest risk profile
        latest_risk = _row_to_dict(
            conn.execute(
                """
                SELECT * FROM sovereign_risk_scores
                WHERE iso_code = ?
                ORDER BY year DESC LIMIT 1
                """,
                (iso,),
            ).fetchone()
        )
        latest_year = int(latest_risk["year"])

        # Latest full granular EFW ratings row + 5Y lag row for exact sub-indicator deltas
        latest_rat = _row_to_dict(
            conn.execute(
                "SELECT * FROM efw_ratings WHERE iso_code = ? AND year = ?",
                (iso, latest_year),
            ).fetchone()
        )
        lag5_rat = _row_to_dict(
            conn.execute(
                "SELECT * FROM efw_ratings WHERE iso_code = ? AND year = ?",
                (iso, latest_year - 5),
            ).fetchone()
        )

        # Regional benchmark averages for latest year
        region = latest_risk.get("wb_region")
        reg_bench = _row_to_dict(
            conn.execute(
                """
                SELECT
                    ROUND(AVG(efw_score), 2) AS avg_efw_score,
                    ROUND(AVG(composite_risk_score), 2) AS avg_composite_risk,
                    ROUND(AVG(inst_decay_risk), 2) AS avg_inst_decay,
                    ROUND(AVG(monetary_stress_risk), 2) AS avg_monetary_stress,
                    ROUND(AVG(capital_siege_risk), 2) AS avg_capital_siege,
                    ROUND(AVG(state_coercion_risk), 2) AS avg_state_coercion,
                    ROUND(AVG(regime_shock_risk), 2) AS avg_regime_shock,
                    COUNT(*) AS peer_count
                FROM sovereign_risk_scores
                WHERE year = ? AND wb_region = ?
                """,
                (latest_year, region),
            ).fetchone()
        )

        # Longitudinal series: combine 1950-1965 historical + 1970-2024 ratings/panel/risk + regional avg
        hist_rows = [
            _row_to_dict(r)
            for r in conn.execute(
                "SELECT year, hist_efw_score FROM efw_historical WHERE iso_code = ? ORDER BY year ASC",
                (iso,),
            ).fetchall()
        ]
        modern_rows = [
            _row_to_dict(r)
            for r in conn.execute(
                """
                SELECT
                    s.year,
                    s.efw_score,
                    s.panel_efw_score,
                    s.composite_risk_score,
                    s.inst_decay_risk,
                    s.monetary_stress_risk,
                    s.capital_siege_risk,
                    s.state_coercion_risk,
                    s.regime_shock_risk,
                    p.panel_area1,
                    p.panel_area2,
                    p.panel_area3,
                    p.panel_area4,
                    p.panel_area5,
                    p.panel_area_stddev
                FROM sovereign_risk_scores s
                LEFT JOIN efw_panel p ON s.iso_code = p.iso_code AND s.year = p.year
                WHERE s.iso_code = ?
                ORDER BY s.year ASC
                """,
                (iso,),
            ).fetchall()
        ]
        reg_series_map = {
            int(r["year"]): round(float(r["reg_efw"]), 2)
            for r in conn.execute(
                """
                SELECT year, AVG(panel_efw_score) AS reg_efw
                FROM sovereign_risk_scores
                WHERE wb_region = ? AND panel_efw_score IS NOT NULL
                GROUP BY year
                """,
                (region,),
            ).fetchall()
        }

        timeline_by_year: dict[int, dict[str, Any]] = {}
        for hr in hist_rows:
            y = int(hr["year"])
            timeline_by_year[y] = {
                "year": y,
                "hist_efw_score": round(float(hr["hist_efw_score"]), 2)
                if hr["hist_efw_score"] is not None
                else None,
                "efw_score": None,
                "panel_efw_score": None,
                "regional_panel_avg": None,
                "composite_risk_score": None,
            }
        for mr in modern_rows:
            y = int(mr["year"])
            entry = timeline_by_year.get(y, {"year": y, "hist_efw_score": None})
            entry.update(mr)
            entry["regional_panel_avg"] = reg_series_map.get(y)
            timeline_by_year[y] = entry

        timeline = [timeline_by_year[k] for k in sorted(timeline_by_year.keys())]

        # Sub-indicator breakdown sorted by vulnerability (lowest score first)
        sub_indicators: list[dict[str, Any]] = []
        for col, (label, domain) in INDICATOR_LABELS.items():
            cur_val = latest_rat.get(col)
            prev_val = lag5_rat.get(col)
            delta_5y = (
                round(float(cur_val) - float(prev_val), 2)
                if (cur_val is not None and prev_val is not None)
                else None
            )
            vuln = round((10.0 - float(cur_val)) * 10.0, 1) if cur_val is not None else None
            sub_indicators.append(
                {
                    "key": col,
                    "label": label,
                    "domain": domain,
                    "score_10": round(float(cur_val), 2) if cur_val is not None else None,
                    "delta_5y": delta_5y,
                    "vulnerability_100": vuln,
                }
            )
        sub_indicators.sort(
            key=lambda x: (x["score_10"] is None, x["score_10"] if x["score_10"] is not None else 99.0)
        )

        # Alerts for this country
        alert_rows = []
        for r in conn.execute(
            """
            SELECT * FROM early_warning_alerts
            WHERE iso_code = ?
            ORDER BY year DESC,
                     CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 ELSE 2 END
            """,
            (iso,),
        ).fetchall():
            d = _row_to_dict(r)
            try:
                d["trigger_metrics"] = json.loads(d.pop("trigger_metrics_json", "{}") or "{}")
            except json.JSONDecodeError:
                d["trigger_metrics"] = {}
            alert_rows.append(d)

        # Peer comparison within same region
        regional_peers = [
            _row_to_dict(r)
            for r in conn.execute(
                """
                SELECT iso_code, country_name, composite_risk_score, threat_tier, efw_score, delta_5y
                FROM sovereign_risk_scores
                WHERE year = ? AND wb_region = ?
                ORDER BY composite_risk_score DESC
                """,
                (latest_year, region),
            ).fetchall()
        ]

        return {
            "generated_at_utc": utc_now_iso(),
            "iso_code": iso,
            "country_name": latest_risk["country_name"],
            "latest_year": latest_year,
            "summary": latest_risk,
            "regional_benchmark": reg_bench,
            "sub_indicators": sub_indicators,
            "timeline": timeline,
            "alerts": alert_rows,
            "regional_peers": regional_peers,
        }
    finally:
        conn.close()


def format_dossier_markdown(payload: dict[str, Any]) -> str:
    """Render a standalone analyst-grade OSINT Country Intelligence Brief in Markdown."""
    s = payload["summary"]
    rb = payload["regional_benchmark"]
    iso = payload["iso_code"]
    cname = payload["country_name"]
    yr = payload["latest_year"]
    ledger = ProvenanceLedger()
    xlsx_hash = (
        ledger.data.get("artifacts", {}).get("efotw_master_xlsx", {}).get("sha256", "N/A")
    )

    def _f(v: Any, d: int = 2, suffix: str = "") -> str:
        if v is None:
            return "N/A"
        return f"{float(v):.{d}f}{suffix}"

    active_alerts = [a for a in payload["alerts"] if int(a["year"]) == yr]
    vuln_top = [x for x in payload["sub_indicators"] if x["score_10"] is not None][:8]
    res_top = [x for x in reversed(payload["sub_indicators"]) if x["score_10"] is not None][:5]

    lines = [
        f"# OSINT SOVEREIGN INTELLIGENCE DOSSIER: {cname.upper()} (`{iso}`)",
        "",
        f"**Classification:** OPEN-SOURCE INTELLIGENCE (OSINT // UNCLASSIFIED)  ",
        f"**Assessment Cycle:** {yr} Data Release (Generated `{payload['generated_at_utc']}`)  ",
        f"**Region / Income Group:** {s.get('wb_region') or 'N/A'} — {s.get('wb_income_group') or 'N/A'}  ",
        f"**Primary Evidence SHA-256:** `{xlsx_hash[:24]}...` (Fraser EFOTW + World Bank/WGI Fused)",
        "",
        "---",
        "",
        "## 1. Executive Threat Assessment",
        "",
        "| Metric | Jurisdiction Value | Regional Benchmark | Operational Interpretation |",
        "| :--- | :---: | :---: | :--- |",
        f"| **Composite Sovereign Risk** | **{_f(s.get('composite_risk_score'))} / 100** | {_f(rb.get('avg_composite_risk'))} / 100 | Threat Tier: **{s.get('threat_tier')}** (Global Risk Rank #{s.get('risk_rank')} of 165) |",
        f"| **EFOTW Headline Score** | **{_f(s.get('efw_score'))} / 10** | {_f(rb.get('avg_efw_score'))} / 10 | Global Freedom Rank #{int(s['efw_rank']) if s.get('efw_rank') else 'N/A'} (Quartile {int(s['efw_quartile']) if s.get('efw_quartile') else 'N/A'}) |",
        f"| **5-Year Regime Velocity (Panel Δ5Y)** | **{_f(s.get('delta_5y'), 3)}** | — | Velocity Z-Score: `{_f(s.get('z_velocity_5y'), 2)}σ` (1Y Δ `{_f(s.get('delta_1y'), 3)}`, 10Y Δ `{_f(s.get('delta_10y'), 3)}`) |",
        f"| **ML Regime Archetype** | **{s.get('regime_archetype')}** | — | Structural Area StdDev: `{_f(s.get('panel_area_stddev'))}` |",
        "",
        "## 2. Five-Vector Threat Decomposition (0–100 Severity Scale)",
        "",
        "| Threat Vector | Risk Score (0–100) | Regional Peer Avg | Delta vs. Region |",
        "| :--- | :---: | :---: | :---: |",
    ]

    vectors = [
        ("Institutional & Judicial Decay (`INST_DECAY`)", "inst_decay_risk", "avg_inst_decay"),
        ("Monetary Collapse & Repression (`MONETARY_STRESS`)", "monetary_stress_risk", "avg_monetary_stress"),
        ("Capital Trap & Parallel FX Siege (`CAPITAL_SIEGE`)", "capital_siege_risk", "avg_capital_siege"),
        ("Longitudinal Regime Velocity Shock (`REGIME_SHOCK`)", "regime_shock_risk", "avg_regime_shock"),
        ("State Asset Capture & Coercion (`STATE_COERCION`)", "state_coercion_risk", "avg_state_coercion"),
    ]
    for label, k_jur, k_reg in vectors:
        jv = s.get(k_jur)
        rv = rb.get(k_reg)
        diff = (float(jv) - float(rv)) if (jv is not None and rv is not None) else None
        sign = "+" if (diff is not None and diff > 0) else ""
        lines.append(
            f"| {label} | **{_f(jv)}** | {_f(rv)} | {sign}{_f(diff)} |"
        )

    lines.extend(["", "## 3. Active Early-Warning Intelligence Alerts", ""])
    if active_alerts:
        for a in active_alerts:
            lines.append(f"- **[{a['severity']}] `{a['alert_type']}` — {a['headline']}**")
            lines.append(f"  - *Quantitative Trigger:* {a['evidence_summary']}")
    else:
        lines.append(
            f"- **NO ACTIVE CRITICAL/HIGH TRIGGERS ({yr}):** Jurisdiction currently operates within baseline thresholds without acute early-warning triggers."
        )

    lines.extend(
        [
            "",
            "## 4. Acute Sub-Indicator Vulnerabilities (Lowest Rated 0–10 Indicators)",
            "",
            "| Sub-Indicator | Domain | Rating (0–10) | 5Y Shift | Vulnerability (0–100) |",
            "| :--- | :--- | :---: | :---: | :---: |",
        ]
    )
    for item in vuln_top:
        d5 = item["delta_5y"]
        d5_str = f"{'+' if d5 and d5 > 0 else ''}{d5:.2f}" if d5 is not None else "N/A"
        lines.append(
            f"| **{item['label']}** | {item['domain']} | {_f(item['score_10'])} | {d5_str} | {_f(item['vulnerability_100'], 1)} |"
        )

    lines.extend(
        [
            "",
            "## 5. Institutional Anchors / Relative Strengths",
            "",
            "| Sub-Indicator | Domain | Rating (0–10) | 5Y Shift |",
            "| :--- | :--- | :---: | :---: |",
        ]
    )
    for item in res_top:
        d5 = item["delta_5y"]
        d5_str = f"{'+' if d5 and d5 > 0 else ''}{d5:.2f}" if d5 is not None else "N/A"
        lines.append(
            f"| {item['label']} | {item['domain']} | **{_f(item['score_10'])}** | {d5_str} |"
        )

    lines.extend(
        [
            "",
            "## 6. Multi-Source Cross-Verification (World Bank WDI & WGI Feeds)",
            "",
            "| External Open-Source Feed | Value | Analytical Notes |",
            "| :--- | :---: | :--- |",
            f"| **WGI Rule of Law (`GOV_WGI_RL.SC`)** | {_f(s.get('wgi_rule_of_law'), 1)} / 100 | Cross-checks EFOTW Area 2 (`{_f(s.get('area2_legal_property'))}/10`) |",
            f"| **WGI Control of Corruption (`GOV_WGI_CC.SC`)** | {_f(s.get('wgi_control_corruption'), 1)} / 100 | Cross-checks Impartial Public Admin (`{_f(s.get('impartial_public_admin'))}/10`) |",
            f"| **WGI Political Stability (`GOV_WGI_PV.SC`)** | {_f(s.get('wgi_political_stability'), 1)} / 100 | Conflict, terrorism & unconstitutional regime-change exposure |",
            f"| **WGI Voice & Accountability (`GOV_WGI_VA.SC`)** | {_f(s.get('wgi_voice_accountability'), 1)} / 100 | Civic space & democratic accountability check |",
            f"| **GDP per Capita, PPP (Const. 2021 $)** | ${_f(s.get('wb_gdp_pcap_ppp'), 0)} | Economic output buffer capacity |",
            f"| **Headline CPI Inflation (World Bank)** | {_f(s.get('wb_cpi_inflation'), 2, '%')} | EFOTW recorded inflation: {_f(s.get('inflation_raw_pct'), 2, '%')} |",
            f"| **Military Expenditure (% of GDP)** | {_f(s.get('wb_mil_exp_gdp'), 2, '%')} | EFOTW Military Interference score: {_f(s.get('military_interference'))}/10 |",
            f"| **Cross-Source Asymmetry Gap** | {_f(s.get('cross_source_gap'), 1)} pts | EFOTW Global Percentile ({_f(s.get('efw_percentile'), 1)}%) minus WGI Civic/Stability Avg |",
            "",
            "---",
            "*Generated automatically by **SOVEREIGN-WATCH** (`efotw_osint`) — Reproducible OSINT Geopolitical Risk Engine.*",
        ]
    )
    return "\n".join(lines) + "\n"


def export_country_dossier(iso_or_name: str, db_path: Path = DB_PATH) -> Path:
    """Build and write a Markdown Country Intelligence Dossier to reports/."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    payload = build_country_dossier_payload(iso_or_name, db_path=db_path)
    md = format_dossier_markdown(payload)
    out_path = REPORTS_DIR / f"OSINT_Dossier_{payload['iso_code']}_{payload['latest_year']}.md"
    out_path.write_text(md, encoding="utf-8")
    return out_path


def generate_global_sitrep_markdown(db_path: Path = DB_PATH) -> Path:
    """Generate an executive Global Geopolitical Risk & Early-Warning SITREP Markdown brief."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    conn = get_connection(db_path)
    try:
        latest_year = int(
            conn.execute("SELECT MAX(year) AS y FROM sovereign_risk_scores").fetchone()["y"]
        )
        top_risk = [
            _row_to_dict(r)
            for r in conn.execute(
                """
                SELECT * FROM sovereign_risk_scores
                WHERE year = ?
                ORDER BY composite_risk_score DESC LIMIT 15
                """,
                (latest_year,),
            ).fetchall()
        ]
        fastest_decay = [
            _row_to_dict(r)
            for r in conn.execute(
                """
                SELECT * FROM sovereign_risk_scores
                WHERE year = ? AND delta_5y IS NOT NULL
                ORDER BY delta_5y ASC LIMIT 12
                """,
                (latest_year,),
            ).fetchall()
        ]
        fastest_reform = [
            _row_to_dict(r)
            for r in conn.execute(
                """
                SELECT * FROM sovereign_risk_scores
                WHERE year = ? AND delta_5y IS NOT NULL AND composite_risk_score < 48.0
                ORDER BY delta_5y DESC LIMIT 8
                """,
                (latest_year,),
            ).fetchall()
        ]
        crit_alerts = [
            _row_to_dict(r)
            for r in conn.execute(
                """
                SELECT * FROM early_warning_alerts
                WHERE year = ? AND severity = 'CRITICAL'
                ORDER BY composite_risk_score DESC LIMIT 18
                """,
                (latest_year,),
            ).fetchall()
        ]
        divergences = [
            _row_to_dict(r)
            for r in conn.execute(
                """
                SELECT * FROM early_warning_alerts
                WHERE year = ? AND alert_type = 'CROSS_SOURCE_DIVERGENCE'
                ORDER BY composite_risk_score DESC LIMIT 10
                """,
                (latest_year,),
            ).fetchall()
        ]
        tier_counts = {
            r["threat_tier"]: int(r["cnt"])
            for r in conn.execute(
                "SELECT threat_tier, COUNT(*) AS cnt FROM sovereign_risk_scores WHERE year = ? GROUP BY threat_tier",
                (latest_year,),
            ).fetchall()
        }
    finally:
        conn.close()

    ledger = ProvenanceLedger()
    audit = ledger.verify_all_artifacts()
    xver = audit.get("cross_verification", {})

    lines = [
        f"# GLOBAL GEOPOLITICAL RISK & EARLY-WARNING SITREP ({latest_year} EDITION)",
        "",
        f"**Platform:** SOVEREIGN-WATCH (`efotw_osint` v1.0)  ",
        f"**Generated UTC:** `{utc_now_iso()}`  ",
        f"**Primary Intelligence Source:** Fraser Institute *Economic Freedom of the World* Master Researcher Dataset (`1950–{latest_year}`, 165 Jurisdictions)  ",
        f"**Secondary Cross-Verification Feeds:** World Bank WDI (`source=2`) & Worldwide Governance Indicators (`source=3`)  ",
        f"**Chain-of-Custody Audit:** **{audit['overall_status']}** ({audit['artifact_count']} SHA-256 artifacts verified; Portal-vs-XLSX agreement: **{xver.get('agreement_pct', 100.0)}%** across {xver.get('countries_cross_checked', 0)} jurisdictions)",
        "",
        "---",
        "",
        "## 1. Global Threat Posture Overview",
        "",
        f"- **CRITICAL Threat Tier (`>= 62.0`):** {tier_counts.get('CRITICAL', 0)} jurisdictions",
        f"- **HIGH Threat Tier (`48.0 – 61.9`):** {tier_counts.get('HIGH', 0)} jurisdictions",
        f"- **ELEVATED Threat Tier (`36.0 – 47.9`):** {tier_counts.get('ELEVATED', 0)} jurisdictions",
        f"- **GUARDED Threat Tier (`25.0 – 35.9`):** {tier_counts.get('GUARDED', 0)} jurisdictions",
        f"- **LOW Threat Tier (`< 25.0`):** {tier_counts.get('LOW', 0)} jurisdictions",
        "",
        "## 2. Top 15 Highest Sovereign Risk Jurisdictions",
        "",
        "| Rank | ISO | Jurisdiction | Composite Risk | Tier | EFW Score | 5Y Panel Δ | Institutional | Monetary | Capital Siege | Regime Archetype |",
        "| :---: | :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |",
    ]
    for r in top_risk:
        d5 = f"{r['delta_5y']:+.2f}" if r.get("delta_5y") is not None else "N/A"
        lines.append(
            f"| {r['risk_rank']} | `{r['iso_code']}` | **{r['country_name']}** | **{r['composite_risk_score']:.2f}** | `{r['threat_tier']}` | {r['efw_score']:.2f} | {d5} | {r['inst_decay_risk']:.1f} | {r['monetary_stress_risk']:.1f} | {r['capital_siege_risk']:.1f} | {r['regime_archetype']} |"
        )

    lines.extend(
        [
            "",
            "## 3. Early-Warning Velocity Watch: Fastest 5-Year Structural Deterioration",
            "",
            "*Computed strictly on the time-consistent `EFW Panel Dataset` (`2019 → 2024`) to eliminate longitudinal indicator-composition bias.*",
            "",
            "| ISO | Jurisdiction | Region | 5Y Panel Δ | Velocity Z-Score | Worst Single-Area 5Y Drop | Current EFW | Composite Risk |",
            "| :---: | :--- | :--- | :---: | :---: | :---: | :---: | :---: |",
        ]
    )
    for r in fastest_decay:
        lines.append(
            f"| `{r['iso_code']}` | **{r['country_name']}** | {r.get('wb_region') or 'N/A'} | **{r['delta_5y']:+.3f}** | `{r['z_velocity_5y']:+.2f}σ` | {r['worst_area_5y_drop']:+.2f} | {r['efw_score']:.2f} | {r['composite_risk_score']:.1f} (`{r['threat_tier']}`) |"
        )

    lines.extend(
        [
            "",
            "## 4. Positive Structural Reformers (Strongest 5-Year Institutional Gains)",
            "",
            "| ISO | Jurisdiction | Region | 5Y Panel Δ | Velocity Z-Score | Current EFW | Threat Tier |",
            "| :---: | :--- | :--- | :---: | :---: | :---: | :---: |",
        ]
    )
    for r in fastest_reform:
        lines.append(
            f"| `{r['iso_code']}` | **{r['country_name']}** | {r.get('wb_region') or 'N/A'} | **{r['delta_5y']:+.3f}** | `{r['z_velocity_5y']:+.2f}σ` | {r['efw_score']:.2f} | `{r['threat_tier']}` |"
        )

    lines.extend(
        [
            "",
            "## 5. Priority Critical Early-Warning Alerts",
            "",
        ]
    )
    for a in crit_alerts:
        lines.append(
            f"- **`[{a['iso_code']}]` {a['headline']}** (`{a['alert_type']}`) — {a['evidence_summary']}"
        )

    lines.extend(
        [
            "",
            "## 6. OSINT Cross-Source Asymmetry Watch (High Market Openness vs. Acute Political/Civic Fragility)",
            "",
        ]
    )
    for d in divergences:
        lines.append(f"- **`[{d['iso_code']}]` {d['country_name']}** — {d['evidence_summary']}")

    lines.extend(
        [
            "",
            "---",
            "*End of Global Geopolitical Risk SITREP — SOVEREIGN-WATCH OSINT Platform.*",
        ]
    )

    out_path = REPORTS_DIR / f"GLOBAL_GEOPOLITICAL_RISK_SITREP_{latest_year}.md"
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out_path
