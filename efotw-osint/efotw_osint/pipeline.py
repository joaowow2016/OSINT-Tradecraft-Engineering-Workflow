"""
End-to-End OSINT Ingestion, Cross-Verification & Intelligence Pipeline Orchestrator.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .analytics import run_risk_and_early_warning_engine
from .collector import (
    collect_efotw_master_xlsx,
    collect_worldbank_enrichment,
    recon_efotw_portal,
)
from .config import DB_PATH, EFOTW_PORTAL_URL
from .database import (
    build_base_tables,
    parse_efotw_master_sheets,
    persist_analytics_outputs,
)
from .provenance import ProvenanceLedger, cross_verify_portal_vs_master


def run_full_osint_pipeline(
    *,
    portal_url: str = EFOTW_PORTAL_URL,
    db_path: Path = DB_PATH,
    enrich_worldbank: bool = True,
    force_refresh: bool = False,
) -> dict[str, Any]:
    """
    Execute the complete SOVEREIGN-WATCH OSINT pipeline:
      1. DOM Reconnaissance on efotw.org dataset portal
      2. Master Researcher XLSX collection + SHA-256 chain-of-custody
      3. Parsing & ISO-3 entity resolution across all 3 EFOTW sheets (1950-2024)
      4. HTML-vs-XLSX cross-verification audit
      5. Live World Bank WDI + WGI open-source intelligence enrichment
      6. Normalized SQLite persistence + Geopolitical Risk & Early-Warning modeling
    """
    ledger = ProvenanceLedger()

    # Step 1: Portal Recon
    recon = recon_efotw_portal(portal_url=portal_url, ledger=ledger, force=force_refresh)

    # Step 2: Collect Master XLSX
    xlsx_path = collect_efotw_master_xlsx(
        recon["discovered_xlsx_url"], ledger=ledger, force=force_refresh
    )

    # Step 3: Parse all 3 sheets + Entity Resolution
    sheets = parse_efotw_master_sheets(xlsx_path)
    df_rat = sheets["ratings"]
    latest_year = int(df_rat["year"].max())

    # Step 4: Cross-Verify discovered internal SPA API (/api/v1/ftw_get_all_data) vs Master XLSX
    latest_rows = df_rat[df_rat["year"] == latest_year]
    master_by_iso = {
        str(r["iso_code"]).strip(): {
            "year": int(r["year"]),
            "efw_score": float(r["efw_score"]) if r["efw_score"] is not None else None,
        }
        for _, r in latest_rows.iterrows()
    }
    xver_report = cross_verify_portal_vs_master(recon["live_rows"], master_by_iso)
    ledger.record_cross_verification(xver_report)

    # Step 5: Live World Bank / WGI Enrichment
    target_isos = set(df_rat["iso_code"].dropna().unique().tolist())
    wb_rows = (
        collect_worldbank_enrichment(
            target_isos=target_isos, ledger=ledger, force=force_refresh
        )
        if enrich_worldbank
        else []
    )

    # Step 6: Build SQLite Base Tables
    base_counts = build_base_tables(sheets, wb_rows, db_path=db_path)

    # Step 7: Run Geopolitical Risk & Early-Warning Engine
    df_risk, alerts = run_risk_and_early_warning_engine(sheets, wb_rows)
    analytics_counts = persist_analytics_outputs(df_risk, alerts, db_path=db_path)

    latest_risk = df_risk[df_risk["year"] == latest_year]
    latest_alerts = [a for a in alerts if int(a["year"]) == latest_year]

    return {
        "latest_year": latest_year,
        "jurisdictions_monitored": int(latest_risk["iso_code"].nunique()),
        "historical_resolved_pct": round(
            float(sheets["historical"]["iso_code"].notna().mean() * 100.0), 2
        ),
        "discovered_xlsx_url": recon["discovered_xlsx_url"],
        "cross_verification": xver_report,
        "table_counts": {**base_counts, **analytics_counts},
        "active_alerts_latest_year": len(latest_alerts),
        "critical_regimes_count": int((latest_risk["threat_tier"] == "CRITICAL").sum()),
        "high_regimes_count": int((latest_risk["threat_tier"] == "HIGH").sum()),
    }
