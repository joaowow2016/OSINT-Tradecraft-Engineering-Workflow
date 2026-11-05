"""
Normalized SQLite Intelligence Store & Entity Resolution Engine.
Ingests all 3 sheets of the Fraser Institute Master XLSX + World Bank/WGI feeds,
resolves historical country entities to ISO-3 codes, and persists computed
geopolitical risk scores and early-warning alerts.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from .config import (
    DB_PATH,
    EFW_PANEL_COLUMN_MAP,
    EFW_RATINGS_COLUMN_MAP,
    HISTORICAL_ENTITY_RESOLUTION,
    WB_INDICATORS,
)


def get_connection(db_path: Path = DB_PATH) -> sqlite3.Connection:
    """Open a SQLite connection configured with WAL mode and Row factory."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def _clean_df_for_sql(df: pd.DataFrame) -> pd.DataFrame:
    """Replace NaN/inf values with None for clean SQLite insertion."""
    out = df.replace([np.inf, -np.inf], np.nan)
    return out.where(pd.notnull(out), None)


def parse_efotw_master_sheets(xlsx_path: Path) -> dict[str, pd.DataFrame]:
    """
    Parse all 3 sheets from the Fraser Institute Master Researcher XLSX:
      1. 'EFW Ratings' (header=3) -> granular 45+ sub-indicators & raw macro figures
      2. 'EFW Panel Dataset' (header=0) -> time-consistent longitudinal series
      3. 'EFW Ratings 1950-1965' (header=0) -> deep historical baseline resolved to ISO-3
    """
    # 1. Sheet 1: EFW Ratings
    raw_ratings = pd.read_excel(xlsx_path, sheet_name="EFW Ratings", header=3)
    available_rat_cols = {
        src: dst for src, dst in EFW_RATINGS_COLUMN_MAP.items() if src in raw_ratings.columns
    }
    df_ratings = raw_ratings[list(available_rat_cols.keys())].rename(columns=available_rat_cols)
    df_ratings = df_ratings.dropna(subset=["year", "iso_code"]).copy()
    df_ratings["year"] = df_ratings["year"].astype(int)
    df_ratings["iso_code"] = df_ratings["iso_code"].astype(str).str.strip()
    df_ratings["country_name"] = df_ratings["country_name"].astype(str).str.strip()

    for col in df_ratings.columns:
        if col not in ("iso_code", "country_name", "wb_region", "wb_income_group", "year"):
            df_ratings[col] = pd.to_numeric(df_ratings[col], errors="coerce")

    # Build canonical Country Name -> ISO-3 dictionary for Entity Resolution
    name_to_iso: dict[str, str] = {}
    for _, row in (
        df_ratings[["country_name", "iso_code"]].drop_duplicates().iterrows()
    ):
        name_to_iso[str(row["country_name"]).strip()] = str(row["iso_code"]).strip()
    name_to_iso.update(HISTORICAL_ENTITY_RESOLUTION)

    # 2. Sheet 2: EFW Panel Dataset
    raw_panel = pd.read_excel(xlsx_path, sheet_name="EFW Panel Dataset", header=0)
    available_pan_cols = {
        src: dst for src, dst in EFW_PANEL_COLUMN_MAP.items() if src in raw_panel.columns
    }
    df_panel = raw_panel[list(available_pan_cols.keys())].rename(columns=available_pan_cols)
    df_panel = df_panel.dropna(subset=["year", "iso_code"]).copy()
    df_panel["year"] = df_panel["year"].astype(int)
    df_panel["iso_code"] = df_panel["iso_code"].astype(str).str.strip()
    df_panel["country_name"] = df_panel["country_name"].astype(str).str.strip()
    for col in df_panel.columns:
        if col not in ("iso_code", "country_name", "year"):
            df_panel[col] = pd.to_numeric(df_panel[col], errors="coerce")

    # 3. Sheet 3: EFW Ratings 1950-1965 (Entity Resolution to ISO-3)
    raw_hist = pd.read_excel(xlsx_path, sheet_name="EFW Ratings 1950-1965", header=0)
    df_hist = raw_hist.rename(
        columns={"Year": "year", "Country": "raw_country_name", "EFW": "hist_efw_score"}
    ).dropna(subset=["year", "raw_country_name"])
    df_hist["year"] = df_hist["year"].astype(int)
    df_hist["raw_country_name"] = df_hist["raw_country_name"].astype(str).str.strip()
    df_hist["hist_efw_score"] = pd.to_numeric(df_hist["hist_efw_score"], errors="coerce")
    df_hist["iso_code"] = df_hist["raw_country_name"].map(name_to_iso)

    return {
        "ratings": df_ratings,
        "panel": df_panel,
        "historical": df_hist,
    }


def build_base_tables(
    sheets: dict[str, pd.DataFrame],
    wb_rows: list[dict[str, Any]],
    db_path: Path = DB_PATH,
) -> dict[str, int]:
    """Write normalized raw & enrichment tables into SQLite with indexes."""
    conn = get_connection(db_path)
    try:
        df_rat = _clean_df_for_sql(sheets["ratings"])
        df_pan = _clean_df_for_sql(sheets["panel"])
        df_hist = _clean_df_for_sql(sheets["historical"])

        df_rat.to_sql("efw_ratings", conn, if_exists="replace", index=False)
        df_pan.to_sql("efw_panel", conn, if_exists="replace", index=False)
        df_hist.to_sql("efw_historical", conn, if_exists="replace", index=False)

        # World Bank / WGI table
        wb_cols = ["iso_code", "year"] + list(WB_INDICATORS.keys())
        if wb_rows:
            df_wb = pd.DataFrame(wb_rows)
            for c in wb_cols:
                if c not in df_wb.columns:
                    df_wb[c] = np.nan
            df_wb = _clean_df_for_sql(df_wb[wb_cols])
        else:
            df_wb = pd.DataFrame(columns=wb_cols)
        df_wb.to_sql("wb_enrichment", conn, if_exists="replace", index=False)

        conn.executescript(
            """
            CREATE INDEX IF NOT EXISTS idx_ratings_iso_year ON efw_ratings(iso_code, year);
            CREATE INDEX IF NOT EXISTS idx_ratings_year ON efw_ratings(year);
            CREATE INDEX IF NOT EXISTS idx_panel_iso_year ON efw_panel(iso_code, year);
            CREATE INDEX IF NOT EXISTS idx_hist_iso_year ON efw_historical(iso_code, year);
            CREATE INDEX IF NOT EXISTS idx_wb_iso_year ON wb_enrichment(iso_code, year);
            """
        )
        conn.commit()
        return {
            "efw_ratings": len(df_rat),
            "efw_panel": len(df_pan),
            "efw_historical": len(df_hist),
            "wb_enrichment": len(df_wb),
        }
    finally:
        conn.close()


def persist_analytics_outputs(
    df_risk: pd.DataFrame,
    alerts: list[dict[str, Any]],
    db_path: Path = DB_PATH,
) -> dict[str, int]:
    """Save computed sovereign risk scores and early-warning alerts to SQLite."""
    conn = get_connection(db_path)
    try:
        clean_risk = _clean_df_for_sql(df_risk)
        clean_risk.to_sql("sovereign_risk_scores", conn, if_exists="replace", index=False)

        if alerts:
            df_alerts = pd.DataFrame(alerts)
            df_alerts["trigger_metrics_json"] = df_alerts["trigger_metrics"].apply(
                lambda d: json.dumps(d) if isinstance(d, dict) else "{}"
            )
            df_alerts = df_alerts.drop(columns=["trigger_metrics"], errors="ignore")
        else:
            df_alerts = pd.DataFrame(
                columns=[
                    "alert_id",
                    "iso_code",
                    "country_name",
                    "wb_region",
                    "year",
                    "severity",
                    "alert_type",
                    "headline",
                    "evidence_summary",
                    "composite_risk_score",
                    "trigger_metrics_json",
                ]
            )
        clean_alerts = _clean_df_for_sql(df_alerts)
        clean_alerts.to_sql("early_warning_alerts", conn, if_exists="replace", index=False)

        conn.executescript(
            """
            CREATE INDEX IF NOT EXISTS idx_risk_iso_year ON sovereign_risk_scores(iso_code, year);
            CREATE INDEX IF NOT EXISTS idx_risk_year_score ON sovereign_risk_scores(year, composite_risk_score DESC);
            CREATE INDEX IF NOT EXISTS idx_alerts_year_sev ON early_warning_alerts(year, severity);
            CREATE INDEX IF NOT EXISTS idx_alerts_iso ON early_warning_alerts(iso_code);
            """
        )
        conn.commit()
        return {
            "sovereign_risk_scores": len(clean_risk),
            "early_warning_alerts": len(clean_alerts),
        }
    finally:
        conn.close()
