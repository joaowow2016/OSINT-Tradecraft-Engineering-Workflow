"""
OSINT Geopolitical Risk & Early-Warning Intelligence Engine.
Computes:
  1. 5 Specialized Threat Vectors (0-100):
     - Institutional & Judicial Decay (INST_DECAY)
     - Monetary Collapse & Repression (MONETARY_STRESS)
     - Capital Trap, Parallel FX & Siege (CAPITAL_SIEGE)
     - State Capture, Expropriation & Coercion (STATE_COERCION)
     - Longitudinal Structural Velocity & Asymmetry (REGIME_SHOCK)
  2. Calendar-Exact Longitudinal Panel Velocities (1Y, 3Y, 5Y, 10Y) & Z-Scores
  3. Unsupervised ML Regime Archetype Clustering (K-Means + 2D PCA)
  4. Automated Early-Warning Alert Rules (6 Threat Typologies + Cross-Source Divergence)
"""

from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler


def _efw_to_risk(series: pd.Series) -> pd.Series:
    """Transform a 0-10 EFOTW freedom/integrity rating into a 0-100 vulnerability score."""
    return ((10.0 - series) * 10.0).clip(lower=0.0, upper=100.0)


def _weighted_nanmean(df: pd.DataFrame, weights: dict[str, float]) -> pd.Series:
    """
    Compute row-wise weighted average across columns in `weights`,
    dynamically re-normalizing weights when individual sub-indicators are NaN.
    """
    num = pd.Series(0.0, index=df.index)
    den = pd.Series(0.0, index=df.index)
    for col, w in weights.items():
        if col not in df.columns:
            continue
        vals = df[col]
        valid = vals.notna()
        num = num.add(vals.fillna(0.0) * w, fill_value=0.0)
        den = den.add(valid.astype(float) * w, fill_value=0.0)
    res = num / den.replace(0.0, np.nan)
    return res


def _prepare_wb_aligned(df_wb: pd.DataFrame, target_years: list[int]) -> pd.DataFrame:
    """
    Align World Bank / WGI indicators by (iso_code, year) with up to 2-year forward-fill
    so 2023 macro/governance releases seamlessly enrich 2024 EFOTW records.
    """
    if df_wb.empty:
        return pd.DataFrame(columns=["iso_code", "year"])

    wb_metrics = [c for c in df_wb.columns if c not in ("iso_code", "year")]
    isos = df_wb["iso_code"].dropna().unique()
    min_y = min(int(df_wb["year"].min()), min(target_years))
    max_y = max(int(df_wb["year"].max()), max(target_years))
    full_idx = pd.MultiIndex.from_product(
        [isos, range(min_y, max_y + 1)], names=["iso_code", "year"]
    )
    indexed = (
        df_wb.drop_duplicates(subset=["iso_code", "year"])
        .set_index(["iso_code", "year"])
        .reindex(full_idx)
        .sort_index()
    )
    for col in wb_metrics:
        indexed[col] = pd.to_numeric(indexed[col], errors="coerce")
        indexed[col] = indexed.groupby(level=0)[col].ffill(limit=2)
    return indexed.reset_index()


def _compute_calendar_deltas(
    df: pd.DataFrame,
    cols: list[str],
    horizons: tuple[int, ...] = (1, 3, 5, 10),
) -> pd.DataFrame:
    """
    Compute exact calendar-year changes S(t) - S(t - k) by joining on (iso_code, year - k).
    Avoids row-shift errors across the 1970-2000 5-year intervals vs 2000-2024 annual intervals.
    """
    out = df.copy()
    present_cols = [c for c in cols if c in out.columns]
    base_lookup = out[["iso_code", "year"] + present_cols].drop_duplicates(
        subset=["iso_code", "year"]
    )

    for k in horizons:
        shifted = base_lookup.copy()
        shifted["year"] = shifted["year"] + k
        rename_map = {c: f"__lag_{k}y_{c}" for c in present_cols}
        shifted = shifted.rename(columns=rename_map)
        out = out.merge(shifted, on=["iso_code", "year"], how="left")
        for c in present_cols:
            out[f"{c}_delta_{k}y"] = out[c] - out[f"__lag_{k}y_{c}"]
        out = out.drop(columns=list(rename_map.values()))

    return out


def assign_threat_tier(score: float | None) -> str:
    """Classify 0-100 composite sovereign risk score into operational OSINT Threat Tiers."""
    if score is None or pd.isna(score):
        return "UNRATED"
    if score >= 62.0:
        return "CRITICAL"
    if score >= 48.0:
        return "HIGH"
    if score >= 36.0:
        return "ELEVATED"
    if score >= 25.0:
        return "GUARDED"
    return "LOW"


def _cluster_regime_archetypes(df_latest: pd.DataFrame) -> pd.DataFrame:
    """
    Unsupervised ML Regime Archetype Clustering (K-Means + 2D PCA) across 165 jurisdictions.
    Labels clusters deterministically from their empirical centroid profiles.
    """
    feature_cols = [
        "inst_decay_risk",
        "monetary_stress_risk",
        "capital_siege_risk",
        "state_coercion_risk",
        "regime_shock_risk",
        "panel_area_stddev",
        "wgi_voice_accountability",
        "wgi_political_stability",
    ]
    available = [c for c in feature_cols if c in df_latest.columns]
    X_raw = df_latest[available].copy()

    imputer = SimpleImputer(strategy="median")
    scaler = StandardScaler()
    X_imp = imputer.fit_transform(X_raw)
    X_scaled = scaler.fit_transform(X_imp)

    n_clusters = min(5, len(df_latest))
    km = KMeans(n_clusters=n_clusters, random_state=42, n_init=20)
    labels = km.fit_predict(X_scaled)

    pca = PCA(n_components=2, random_state=42)
    coords = pca.fit_transform(X_scaled)

    res = df_latest[["iso_code"]].copy()
    res["cluster_id"] = labels
    res["pca_x"] = np.round(coords[:, 0], 4)
    res["pca_y"] = np.round(coords[:, 1], 4)

    # Inspect cluster centroids in original units to assign accurate OSINT archetype names
    tmp = df_latest.copy()
    tmp["cluster_id"] = labels
    centroids = tmp.groupby("cluster_id")[
        [
            "composite_risk_score",
            "inst_decay_risk",
            "monetary_stress_risk",
            "capital_siege_risk",
            "wgi_voice_accountability",
        ]
    ].mean()

    # Deterministic assignment based on empirical profile
    cluster_names: dict[int, str] = {}
    remaining = set(centroids.index.tolist())

    # 1. Lowest overall risk -> Resilient Open Democracies
    best_cid = int(centroids.loc[list(remaining), "composite_risk_score"].idxmin())
    cluster_names[best_cid] = "Resilient Rule-of-Law Economies"
    remaining.remove(best_cid)

    # 2. Highest overall composite risk -> Systemic Fragility / Coercive States
    if remaining:
        worst_cid = int(centroids.loc[list(remaining), "composite_risk_score"].idxmax())
        cluster_names[worst_cid] = "Acute Crisis & Coercive Regimes"
        remaining.remove(worst_cid)

    # 3. Highest monetary + capital siege stress among remaining
    if remaining:
        mon_score = (
            centroids.loc[list(remaining), "monetary_stress_risk"]
            + centroids.loc[list(remaining), "capital_siege_risk"]
        )
        mon_cid = int(mon_score.idxmax())
        cluster_names[mon_cid] = "Capital-Locked & Monetary Stress States"
        remaining.remove(mon_cid)

    # 4. Among remaining two: lower Voice/Accountability vs Moderate/Transitional
    if remaining:
        rem_list = list(remaining)
        if len(rem_list) >= 2 and "wgi_voice_accountability" in centroids.columns:
            illib_cid = int(centroids.loc[rem_list, "wgi_voice_accountability"].idxmin())
            cluster_names[illib_cid] = "State-Directed / Illiberal Market Hubs"
            remaining.remove(illib_cid)
        for cid in remaining:
            cluster_names[int(cid)] = "Hybrid Institutional / Transitional States"

    res["regime_archetype"] = res["cluster_id"].map(cluster_names)
    return res[["iso_code", "regime_archetype", "pca_x", "pca_y"]]


def run_risk_and_early_warning_engine(
    sheets: dict[str, pd.DataFrame],
    wb_rows: list[dict[str, Any]],
) -> tuple[pd.DataFrame, list[dict[str, Any]]]:
    """
    Execute the end-to-end OSINT Geopolitical Risk & Early-Warning Model across
    all jurisdictions and years, returning (df_risk, early_warning_alerts).
    """
    df_rat = sheets["ratings"].copy()
    df_pan = sheets["panel"].copy()
    df_wb_raw = pd.DataFrame(wb_rows) if wb_rows else pd.DataFrame()

    # Merge Ratings + Panel Dataset on (iso_code, year)
    pan_cols = [c for c in df_pan.columns if c != "country_name"]
    df = df_rat.merge(df_pan[pan_cols], on=["iso_code", "year"], how="left")

    # Align & merge World Bank / WGI enrichment
    if not df_wb_raw.empty:
        wb_aligned = _prepare_wb_aligned(
            df_wb_raw, sorted(df["year"].unique().astype(int).tolist())
        )
        df = df.merge(wb_aligned, on=["iso_code", "year"], how="left")
    else:
        for k in (
            "wb_gdp_pcap_ppp",
            "wb_cpi_inflation",
            "wb_trade_gdp",
            "wb_mil_exp_gdp",
            "wgi_rule_of_law",
            "wgi_control_corruption",
            "wgi_political_stability",
            "wgi_voice_accountability",
        ):
            df[k] = np.nan

    # Compute calendar-exact longitudinal shifts on Panel series & key OSINT sub-indicators
    delta_targets = [
        "panel_efw_score",
        "panel_area1",
        "panel_area2",
        "panel_area3",
        "panel_area4",
        "panel_area5",
        "efw_score",
        "judicial_independence",
        "military_interference",
        "property_rights",
        "black_market_fx",
        "capital_controls",
        "impartial_public_admin",
    ]
    df = _compute_calendar_deltas(df, delta_targets, horizons=(1, 3, 5, 10))

    # Build temporary 0-100 risk transforms for each granular sub-indicator
    r_df = pd.DataFrame(index=df.index)
    sub_cols = [
        "judicial_independence",
        "impartial_courts",
        "military_interference",
        "property_rights",
        "legal_integrity",
        "impartial_public_admin",
        "area2_legal_property",
        "inflation_score",
        "inflation_stddev",
        "money_growth",
        "foreign_currency_accounts",
        "interest_rate_controls",
        "area3_sound_money",
        "black_market_fx",
        "capital_controls",
        "financial_openness",
        "foreign_asset_protection",
        "freedom_to_visit",
        "area4_trade_freedom",
        "state_ownership",
        "bank_ownership",
        "conscription",
        "business_distortion",
        "gov_investment",
        "area1_size_of_gov",
    ]
    for col in sub_cols:
        if col in df.columns:
            r_df[f"r_{col}"] = _efw_to_risk(df[col])

    # WGI 0-100 governance risk inversions (100 - governance_score)
    r_df["r_wgi_rl"] = (100.0 - df["wgi_rule_of_law"]).clip(0.0, 100.0)
    r_df["r_wgi_pv"] = (100.0 - df["wgi_political_stability"]).clip(0.0, 100.0)
    r_df["r_wgi_cc"] = (100.0 - df["wgi_control_corruption"]).clip(0.0, 100.0)

    # 1. Vector 1: Institutional & Judicial Decay Risk (0-100)
    inst_efw = _weighted_nanmean(
        r_df,
        {
            "r_judicial_independence": 0.22,
            "r_military_interference": 0.22,
            "r_impartial_courts": 0.15,
            "r_property_rights": 0.15,
            "r_legal_integrity": 0.13,
            "r_impartial_public_admin": 0.13,
        },
    ).fillna(r_df.get("r_area2_legal_property", pd.Series(50.0, index=df.index)))
    r_df["inst_efw"] = inst_efw
    df["inst_decay_risk"] = _weighted_nanmean(
        r_df, {"inst_efw": 0.80, "r_wgi_rl": 0.10, "r_wgi_pv": 0.10}
    ).round(2)

    # 2. Vector 2: Monetary Collapse & Repression Risk (0-100)
    df["monetary_stress_risk"] = (
        _weighted_nanmean(
            r_df,
            {
                "r_inflation_score": 0.30,
                "r_inflation_stddev": 0.20,
                "r_money_growth": 0.15,
                "r_foreign_currency_accounts": 0.20,
                "r_interest_rate_controls": 0.15,
            },
        )
        .fillna(r_df.get("r_area3_sound_money", pd.Series(35.0, index=df.index)))
        .round(2)
    )

    # 3. Vector 3: Capital Trap, Parallel FX & Sovereign Siege Risk (0-100)
    df["capital_siege_risk"] = (
        _weighted_nanmean(
            r_df,
            {
                "r_black_market_fx": 0.30,
                "r_capital_controls": 0.25,
                "r_financial_openness": 0.20,
                "r_foreign_asset_protection": 0.15,
                "r_freedom_to_visit": 0.10,
            },
        )
        .fillna(r_df.get("r_area4_trade_freedom", pd.Series(35.0, index=df.index)))
        .round(2)
    )

    # 4. Vector 4: State Capture, Expropriation & Mobilization Risk (0-100)
    coerc_efw = _weighted_nanmean(
        r_df,
        {
            "r_state_ownership": 0.30,
            "r_bank_ownership": 0.20,
            "r_conscription": 0.20,
            "r_business_distortion": 0.15,
            "r_gov_investment": 0.15,
        },
    ).fillna(r_df.get("r_area1_size_of_gov", pd.Series(40.0, index=df.index)))
    r_df["coerc_efw"] = coerc_efw
    df["state_coercion_risk"] = _weighted_nanmean(
        r_df, {"coerc_efw": 0.85, "r_wgi_cc": 0.15}
    ).round(2)

    # 5. Vector 5: Longitudinal Structural Velocity & Asymmetry (REGIME_SHOCK, 0-100)
    # Standardize 5-year panel velocity against global historical distribution
    d5 = df["panel_efw_score_delta_5y"].fillna(df["efw_score_delta_5y"])
    d3 = df["panel_efw_score_delta_3y"].fillna(df["efw_score_delta_3y"])
    d1 = df["panel_efw_score_delta_1y"].fillna(df["efw_score_delta_1y"])
    d10 = df["panel_efw_score_delta_10y"].fillna(df["efw_score_delta_10y"])

    df["delta_1y"] = d1.round(3)
    df["delta_3y"] = d3.round(3)
    df["delta_5y"] = d5.round(3)
    df["delta_10y"] = d10.round(3)

    d5_mean = float(d5.mean()) if d5.notna().any() else 0.0
    d5_std = float(d5.std()) if (d5.notna().any() and float(d5.std()) > 1e-6) else 0.45
    df["z_velocity_5y"] = ((d5 - d5_mean) / d5_std).round(3)

    # Worst single-area 5Y drop across Areas 1-5
    area_d5_cols = [f"panel_area{i}_delta_5y" for i in range(1, 6) if f"panel_area{i}_delta_5y" in df.columns]
    df["worst_area_5y_drop"] = df[area_d5_cols].min(axis=1).round(3) if area_d5_cols else np.nan

    # Map downward velocity + worst-area drop + structural asymmetry onto [0, 100]
    downward_5y_component = ((-d5.fillna(0.0)).clip(lower=-0.5, upper=2.0) + 0.5) / 2.5 * 55.0
    worst_area_component = ((-df["worst_area_5y_drop"].fillna(0.0)).clip(lower=0.0, upper=2.5) / 2.5) * 25.0
    asymmetry_component = (df["panel_area_stddev"].fillna(1.0).clip(lower=0.3, upper=2.8) - 0.3) / 2.5 * 20.0
    df["regime_shock_risk"] = (
        (downward_5y_component + worst_area_component + asymmetry_component)
        .clip(0.0, 100.0)
        .round(2)
    )

    # Composite Sovereign Risk Score (0-100)
    df["composite_risk_score"] = (
        _weighted_nanmean(
            df,
            {
                "inst_decay_risk": 0.28,
                "monetary_stress_risk": 0.20,
                "capital_siege_risk": 0.20,
                "regime_shock_risk": 0.18,
                "state_coercion_risk": 0.14,
            },
        )
        .clip(0.0, 100.0)
        .round(2)
    )

    df["threat_tier"] = df["composite_risk_score"].apply(assign_threat_tier)

    # Compute Cross-Source OSINT Divergence Index:
    # EFOTW Percentile (0-100 within year) minus WGI Political Stability / Voice average (0-100)
    df["efw_percentile"] = (
        df.groupby("year")["efw_score"].rank(pct=True) * 100.0
    ).round(1)
    wgi_dem_stab = df[["wgi_political_stability", "wgi_voice_accountability"]].mean(axis=1)
    df["cross_source_gap"] = (df["efw_percentile"] - wgi_dem_stab).round(2)

    # Cluster Regime Archetypes on latest cross-section (2024) and propagate to ISO-3
    latest_year = int(df["year"].max())
    df_latest = df[df["year"] == latest_year].copy()
    clusters_df = _cluster_regime_archetypes(df_latest)
    df = df.merge(clusters_df, on="iso_code", how="left")

    # Compute Sovereign Risk Rank in each year (1 = highest risk)
    df["risk_rank"] = (
        df.groupby("year")["composite_risk_score"]
        .rank(ascending=False, method="min")
        .astype("Int64")
    )

    # Generate Structured Early-Warning Intelligence Alerts (for recent monitoring window 2021-2024)
    alerts = _generate_early_warning_alerts(df[df["year"] >= latest_year - 3].copy())

    keep_cols = [
        "year",
        "iso_code",
        "country_name",
        "wb_region",
        "wb_income_group",
        "efw_score",
        "efw_rank",
        "efw_quartile",
        "efw_percentile",
        "panel_efw_score",
        "panel_area_stddev",
        "composite_risk_score",
        "risk_rank",
        "threat_tier",
        "regime_archetype",
        "inst_decay_risk",
        "monetary_stress_risk",
        "capital_siege_risk",
        "state_coercion_risk",
        "regime_shock_risk",
        "delta_1y",
        "delta_3y",
        "delta_5y",
        "delta_10y",
        "z_velocity_5y",
        "worst_area_5y_drop",
        "cross_source_gap",
        "pca_x",
        "pca_y",
        # Key indicators cached for fast watchlist / chart rendering
        "area1_size_of_gov",
        "area2_legal_property",
        "area3_sound_money",
        "area4_trade_freedom",
        "area5_regulation",
        "judicial_independence",
        "military_interference",
        "property_rights",
        "black_market_fx",
        "capital_controls",
        "foreign_currency_accounts",
        "state_ownership",
        "conscription",
        "impartial_public_admin",
        "inflation_raw_pct",
        "wb_gdp_pcap_ppp",
        "wb_cpi_inflation",
        "wb_trade_gdp",
        "wb_mil_exp_gdp",
        "wgi_rule_of_law",
        "wgi_control_corruption",
        "wgi_political_stability",
        "wgi_voice_accountability",
    ]
    present_keep = [c for c in keep_cols if c in df.columns]
    return df[present_keep].sort_values(["year", "composite_risk_score"], ascending=[False, False]), alerts


def _fmt(val: Any, decimals: int = 2) -> str:
    if val is None or pd.isna(val):
        return "N/A"
    return f"{float(val):.{decimals}f}"


def _generate_early_warning_alerts(df_recent: pd.DataFrame) -> list[dict[str, Any]]:
    """
    Evaluate 6 deterministic, transparent OSINT Early-Warning Alert Rules
    with exact quantitative trigger evidence.
    """
    alerts: list[dict[str, Any]] = []

    for _, r in df_recent.iterrows():
        iso = str(r["iso_code"])
        cname = str(r["country_name"])
        reg = str(r.get("wb_region") or "Unclassified")
        yr = int(r["year"])
        comp = float(r["composite_risk_score"]) if pd.notna(r["composite_risk_score"]) else 0.0

        mil = r.get("military_interference")
        jud = r.get("judicial_independence")
        prop = r.get("property_rights")
        bm_fx = r.get("black_market_fx")
        cap_c = r.get("capital_controls")
        fx_acc = r.get("foreign_currency_accounts")
        a3 = r.get("area3_sound_money")
        infl_sc = r.get("inflation_score")
        infl_raw = r.get("inflation_raw_pct")
        state_own = r.get("state_ownership")
        f_asset = r.get("foreign_asset_protection")
        p_a2_d5 = r.get("panel_area2_delta_5y")
        p_a3_d5 = r.get("panel_area3_delta_5y")
        jud_d5 = r.get("judicial_independence_delta_5y")
        mil_d5 = r.get("military_interference_delta_5y")
        bm_d3 = r.get("black_market_fx_delta_3y")
        wgi_pv = r.get("wgi_political_stability")
        wgi_va = r.get("wgi_voice_accountability")
        efw_pct = r.get("efw_percentile")

        # RULE 1: COUP / MILITARY INTERFERENCE & JUDICIAL SUBJUGATION
        if (pd.notna(mil) and mil <= 3.3 and ((pd.notna(jud) and jud <= 3.8) or (pd.notna(p_a2_d5) and p_a2_d5 <= -0.5))) or (
            pd.notna(mil_d5) and mil_d5 <= -1.8
        ):
            sev = "CRITICAL" if (pd.notna(mil) and mil <= 2.2) or comp >= 60 else "HIGH"
            alerts.append(
                {
                    "alert_id": f"{yr}-{iso}-MIL-COUP",
                    "iso_code": iso,
                    "country_name": cname,
                    "wb_region": reg,
                    "year": yr,
                    "severity": sev,
                    "alert_type": "COUP_MILITARY_CAPTURE",
                    "headline": f"Military Interference & Judicial Subjugation ({cname})",
                    "evidence_summary": (
                        f"Military interference rating at {_fmt(mil)}/10 (5Y Δ {_fmt(mil_d5)}), "
                        f"paired with judicial independence at {_fmt(jud)}/10 and WGI Political Stability {_fmt(wgi_pv, 1)}/100."
                    ),
                    "composite_risk_score": comp,
                    "trigger_metrics": {
                        "military_interference": _fmt(mil),
                        "military_5y_delta": _fmt(mil_d5),
                        "judicial_independence": _fmt(jud),
                        "wgi_political_stability": _fmt(wgi_pv, 1),
                    },
                }
            )

        # RULE 2: PARALLEL FX & CAPITAL FLIGHT LOCK-IN
        if (
            (pd.notna(bm_fx) and bm_fx <= 5.0)
            or (pd.notna(cap_c) and cap_c <= 1.6 and pd.notna(fx_acc) and fx_acc <= 2.5)
            or (pd.notna(bm_d3) and bm_d3 <= -2.5)
        ):
            sev = "CRITICAL" if (pd.notna(bm_fx) and bm_fx <= 1.5) else "HIGH"
            alerts.append(
                {
                    "alert_id": f"{yr}-{iso}-FX-SIEGE",
                    "iso_code": iso,
                    "country_name": cname,
                    "wb_region": reg,
                    "year": yr,
                    "severity": sev,
                    "alert_type": "PARALLEL_FX_CAPITAL_TRAP",
                    "headline": f"Parallel FX Spread / Capital Flight Controls ({cname})",
                    "evidence_summary": (
                        f"Black-market exchange rate score dropped to {_fmt(bm_fx)}/10 (3Y Δ {_fmt(bm_d3)}), "
                        f"capital controls at {_fmt(cap_c)}/10, foreign currency account freedom at {_fmt(fx_acc)}/10."
                    ),
                    "composite_risk_score": comp,
                    "trigger_metrics": {
                        "black_market_fx": _fmt(bm_fx),
                        "black_market_3y_delta": _fmt(bm_d3),
                        "capital_controls": _fmt(cap_c),
                        "foreign_currency_accounts": _fmt(fx_acc),
                    },
                }
            )

        # RULE 3: MONETARY DISINTEGRATION / HYPERINFLATIONARY SPIRAL
        if (pd.notna(a3) and a3 <= 5.0) or (pd.notna(p_a3_d5) and p_a3_d5 <= -2.0) or (
            pd.notna(infl_sc) and infl_sc <= 3.0
        ):
            sev = "CRITICAL" if (pd.notna(a3) and a3 <= 3.5) else "HIGH"
            alerts.append(
                {
                    "alert_id": f"{yr}-{iso}-MONETARY",
                    "iso_code": iso,
                    "country_name": cname,
                    "wb_region": reg,
                    "year": yr,
                    "severity": sev,
                    "alert_type": "MONETARY_DISINTEGRATION",
                    "headline": f"Acute Monetary Debasement & Inflation Shock ({cname})",
                    "evidence_summary": (
                        f"Area 3 Sound Money at {_fmt(a3)}/10 (5Y Panel Δ {_fmt(p_a3_d5)}), "
                        f"inflation rating {_fmt(infl_sc)}/10 (recorded inflation {_fmt(infl_raw, 1)}%)."
                    ),
                    "composite_risk_score": comp,
                    "trigger_metrics": {
                        "area3_sound_money": _fmt(a3),
                        "area3_5y_delta": _fmt(p_a3_d5),
                        "inflation_score": _fmt(infl_sc),
                        "inflation_raw_pct": _fmt(infl_raw, 1),
                    },
                }
            )

        # RULE 4: AUTOCRATIC / JUDICIAL EROSION (EARLY-WARNING VELOCITY DETECTOR)
        if (pd.notna(p_a2_d5) and p_a2_d5 <= -0.60) or (pd.notna(jud_d5) and jud_d5 <= -1.20):
            sev = "CRITICAL" if (pd.notna(p_a2_d5) and p_a2_d5 <= -1.10) else "HIGH"
            alerts.append(
                {
                    "alert_id": f"{yr}-{iso}-JUD-EROSION",
                    "iso_code": iso,
                    "country_name": cname,
                    "wb_region": reg,
                    "year": yr,
                    "severity": sev,
                    "alert_type": "AUTOCRATIC_JUDICIAL_EROSION",
                    "headline": f"Accelerated 5-Year Rule-of-Law Erosion ({cname})",
                    "evidence_summary": (
                        f"Time-consistent Panel Area 2 (Legal System & Property Rights) fell {_fmt(p_a2_d5)} pts over 5 years; "
                        f"Judicial Independence 5Y shift is {_fmt(jud_d5)} pts (current {_fmt(jud)}/10)."
                    ),
                    "composite_risk_score": comp,
                    "trigger_metrics": {
                        "panel_area2_5y_delta": _fmt(p_a2_d5),
                        "judicial_5y_delta": _fmt(jud_d5),
                        "judicial_independence": _fmt(jud),
                        "z_velocity_5y": _fmt(r.get("z_velocity_5y")),
                    },
                }
            )

        # RULE 5: SOVEREIGN EXPROPRIATION & STATE ASSET CAPTURE
        if pd.notna(prop) and prop <= 3.0 and (
            (pd.notna(state_own) and state_own <= 3.2) or (pd.notna(f_asset) and f_asset <= 3.2)
        ):
            sev = "CRITICAL" if prop <= 2.0 else "HIGH"
            alerts.append(
                {
                    "alert_id": f"{yr}-{iso}-EXPROP",
                    "iso_code": iso,
                    "country_name": cname,
                    "wb_region": reg,
                    "year": yr,
                    "severity": sev,
                    "alert_type": "EXPROPRIATION_STATE_TAKEOVER",
                    "headline": f"Sovereign Expropriation & State Capture Exposure ({cname})",
                    "evidence_summary": (
                        f"Property rights security at {_fmt(prop)}/10, state asset independence at {_fmt(state_own)}/10, "
                        f"and foreign asset protection at {_fmt(f_asset)}/10."
                    ),
                    "composite_risk_score": comp,
                    "trigger_metrics": {
                        "property_rights": _fmt(prop),
                        "state_ownership": _fmt(state_own),
                        "foreign_asset_protection": _fmt(f_asset),
                    },
                }
            )

        # RULE 6: OSINT CROSS-SOURCE DIVERGENCE (OPEN MARKETS MASKING POLITICAL/VOICE INSTABILITY)
        if pd.notna(efw_pct) and efw_pct >= 55.0 and (
            (pd.notna(wgi_pv) and wgi_pv <= 33.0) or (pd.notna(wgi_va) and wgi_va <= 28.0)
        ):
            alerts.append(
                {
                    "alert_id": f"{yr}-{iso}-DIVERGENCE",
                    "iso_code": iso,
                    "country_name": cname,
                    "wb_region": reg,
                    "year": yr,
                    "severity": "ELEVATED",
                    "alert_type": "CROSS_SOURCE_DIVERGENCE",
                    "headline": f"Cross-Source Asymmetry: Market Openness vs. Political/Civic Risk ({cname})",
                    "evidence_summary": (
                        f"Ranks in top {100.0 - float(efw_pct):.0f}% of global economic freedom ({_fmt(r.get('efw_score'))}/10), "
                        f"but WGI cross-verification flags Political Stability at {_fmt(wgi_pv, 1)}/100 and Voice/Accountability at {_fmt(wgi_va, 1)}/100."
                    ),
                    "composite_risk_score": comp,
                    "trigger_metrics": {
                        "efw_percentile": _fmt(efw_pct, 1),
                        "efw_score": _fmt(r.get("efw_score")),
                        "wgi_political_stability": _fmt(wgi_pv, 1),
                        "wgi_voice_accountability": _fmt(wgi_va, 1),
                    },
                }
            )

    sev_rank = {"CRITICAL": 0, "HIGH": 1, "ELEVATED": 2, "WATCH": 3}
    alerts.sort(
        key=lambda a: (-int(a["year"]), sev_rank.get(a["severity"], 9), -float(a["composite_risk_score"]))
    )
    return alerts
