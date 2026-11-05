# SOVEREIGN-WATCH (`efotw-osint`)

![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-38bdf8.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-10b981.svg)
![OSINT Provenance](https://img.shields.io/badge/SHA--256_Provenance-Verified-10b981.svg)
![Jurisdictions](https://img.shields.io/badge/Jurisdictions-165_(1950--2024)-f97316.svg)

**Open-Source Intelligence (OSINT) Geopolitical Risk, Institutional Decay & Early-Warning Platform**  
Built in Python on the **Fraser Institute *Economic Freedom of the World* (EFOTW) Master Researcher Dataset (1950–2024)** fused with live **World Bank (WDI)** and **Worldwide Governance Indicators (WGI)** REST APIs.

---

## 1. OSINT Tradecraft & Engineering Architecture

Unlike standard data-analysis scripts that rely on static CSV downloads and unverified averages, **SOVEREIGN-WATCH** implements a five-stage intelligence engineering workflow:

1. **Dynamic Target Reconnaissance (`efotw_osint/collector.py`)**
   - Inspects the target SPA portal (`https://efotw.org/economic-freedom/dataset?...`) and parses embedded `Drupal.settings` JavaScript bundles (`html.min.js` & `scripts.min.js`).
   - Dynamically discovers both the **Researcher Master XLSX URL** (`efotw-2026-master-index-data-for-researchers-iso.xlsx`) and the **undocumented internal SPA JSON API** (`https://efotw.org/api/v1/ftw_get_all_data`).
2. **Cryptographic Chain-of-Custody & Cross-Verification (`efotw_osint/provenance.py`)**
   - Computes **SHA-256 digests**, byte counts, HTTP metadata, and UTC retrieval timestamps for every raw artifact in `data/raw/manifest.json`.
   - Runs an automated **165-for-165 ISO-3 Cross-Verification Audit** comparing the live portal API (`/api/v1/ftw_get_all_data`) against the Researcher Master XLSX (`EFW Ratings` 2024) — confirming **100.0% agreement** with zero silent tampering or drift.
3. **Full-Spectrum Entity Resolution & Longitudinal Store (`efotw_osint/database.py`)**
   - Ingests all **3 sheets** of the researcher dataset into normalized SQLite (`data/sovereign_watch.db`):
     - `efw_ratings`: 5,115 country-year records across 165 ISO-3 jurisdictions (`1970–2024`) with **45+ granular sub-indicators** and raw macro figures.
     - `efw_panel`: 5,115 time-consistent Panel Dataset records (`1970–2024`) engineered to prevent indicator-addition bias during multi-year velocity screening.
     - `efw_historical`: 458 historical records (`1950–1965`) with **100% deterministic entity resolution** mapping legacy names (`Russia`, `Venezuela`, `Iran`, `Turkey`, `Hong Kong`, `Korea, South`, etc.) to ISO-3 codes.
     - `wb_enrichment`: Live parallel ingestion of **8 World Bank WDI (`source=2`) & WGI (`source=3`) indicators** (`GOV_WGI_RL.SC`, `GOV_WGI_CC.SC`, `GOV_WGI_PV.SC`, `GOV_WGI_VA.SC`, `NY.GDP.PCAP.PP.KD`, `FP.CPI.TOTL.ZG`, `NE.TRD.GNFS.ZS`, `MS.MIL.XPND.GD.ZS`).
4. **Geopolitical Risk & Early-Warning Engine (`efotw_osint/analytics.py`)**
   - Decomposes sovereign fragility into **5 Threat Vectors (0–100 scale)**:
     1. `inst_decay_risk` (*28%*) — Judicial independence, military interference, impartial courts, property rights, legal integrity, public administration impartiality + WGI Rule of Law & Political Stability.
     2. `monetary_stress_risk` (*20%*) — Inflation severity, inflation volatility, money growth, foreign currency bank account restrictions, and negative real interest rate controls.
     3. `capital_siege_risk` (*20%*) — Black-market exchange rate spreads, capital controls, financial openness, foreign asset protection, and cross-border movement restrictions.
     4. `regime_shock_risk` (*18%*) — Exact calendar-year longitudinal shifts (`Δ1Y`, `Δ3Y`, `Δ5Y`, `Δ10Y`) on the time-consistent Panel Dataset, standardized 5Y velocity Z-scores (`σ`), worst single-area 5Y drop, and cross-area structural asymmetry (`Std. Dev. of Areas 1–5`).
     5. `state_coercion_risk` (*14%*) — State asset ownership, bank ownership, military conscription, business distortion, and WGI Corruption risk.
   - **Unsupervised ML Regime Clustering**: `StandardScaler` + `KMeans(k=5)` + `PCA(2D)` classifies all 165 jurisdictions into empirical regime archetypes.
   - **6 Deterministic Early-Warning Alert Rules**:
     - `COUP_MILITARY_CAPTURE`
     - `PARALLEL_FX_CAPITAL_TRAP`
     - `MONETARY_DISINTEGRATION`
     - `AUTOCRATIC_JUDICIAL_EROSION`
     - `EXPROPRIATION_STATE_TAKEOVER`
     - `CROSS_SOURCE_DIVERGENCE` (flags jurisdictions where high commercial openness masks acute WGI political instability or civic repression).
5. **Dual Analyst Interfaces (`cli.py` + `efotw_osint/server.py`)**
   - **Tactical Rich CLI**: Terminal tables, SHA-256 audits, early-warning filters, and automated Markdown SITREP / Country Dossier generation.
   - **Interactive Web Workbench (`0.0.0.0:8000`)**: Zero-CDN self-hosted Plotly choropleth world map, 5-year shock quadrant, filterable 165-country watchlist, alert feed, 75-year Country Dossier inspector (`1950–2024`), Cross-Source Correlation Lab, 2D PCA Regime Map, and live SHA-256 Chain-of-Custody Vault.

---

## 2. Quickstart & CLI Usage

```bash
cd /home/user/efotw-osint

# 1. Run full OSINT recon, collection, SHA-256 verification, WGI fusion & risk modeling
python3 cli.py ingest

# 2. Verify SHA-256 chain-of-custody & 165/165 portal API cross-audit
python3 cli.py verify

# 3. View Top Sovereign Risk Watchlist (or fastest 5-year structural decay with --decay)
python3 cli.py watchlist --limit 20
python3 cli.py watchlist --decay --limit 15

# 4. Inspect Active Early-Warning Triggers
python3 cli.py alerts --severity CRITICAL --year 2024

# 5. Generate & export a Country Intelligence Dossier (ISO-3 or Country Name)
python3 cli.py dossier BRA
python3 cli.py dossier VEN

# 6. Generate Global Geopolitical Risk SITREP
python3 cli.py sitrep

# 7. Launch the Interactive Analyst Web Workbench on 0.0.0.0:8000
python3 cli.py serve --host 0.0.0.0 --port 8000
```

---

## 3. REST API Reference

| Endpoint | Description |
| :--- | :--- |
| `GET /api/overview` | Executive KPIs, Threat Tier & ML Archetype counts, regional risk posture, top 5Y decay & reformers |
| `GET /api/watchlist?year=2024&tier=...&region=...` | Full 165-jurisdiction dataset with all 5 Threat Vectors, Panel velocities & WGI metrics |
| `GET /api/alerts?year=2024&severity=CRITICAL` | Structured early-warning alerts with quantitative trigger payloads |
| `GET /api/country/<ISO_OR_NAME>` | Complete 1950–2024 Country Intelligence Dossier JSON |
| `GET /api/dossier/<ISO_OR_NAME>.md` | Downloadable Markdown Country Intelligence Brief |
| `GET /api/provenance` | Live disk SHA-256 hash verification & 165-country cross-source audit |
