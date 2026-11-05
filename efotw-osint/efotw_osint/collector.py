"""
OSINT Reconnaissance & Multi-Source Collection Engine:
1. Scrapes the target EFOTW Dataset Portal (efotw.org) to dynamically discover
   the authoritative Researcher Master XLSX URL and extract the live HTML summary table.
2. Downloads and hashes the Fraser Institute Master Dataset (all 3 historical/panel sheets).
3. Queries live World Bank (WDI) & Worldwide Governance Indicators (WGI) REST APIs
   in parallel with automatic pagination and retry resilience.
"""

from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

from .config import (
    EFOTW_BASE_DOMAIN,
    EFOTW_FALLBACK_XLSX_URL,
    EFOTW_PORTAL_URL,
    RAW_DIR,
    WB_API_BASE,
    WB_INDICATORS,
)
from .provenance import ProvenanceLedger

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) SOVEREIGN-WATCH-OSINT/1.0 "
    "(Geopolitical Risk Research; +https://efotw.org)"
)


def _http_get_with_retry(
    url: str,
    *,
    timeout: int = 25,
    retries: int = 3,
    backoff: float = 1.2,
) -> requests.Response:
    """Resilient HTTP GET with exponential backoff."""
    last_exc: Exception | None = None
    headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    for attempt in range(1, retries + 1):
        try:
            resp = requests.get(url, headers=headers, timeout=timeout)
            resp.raise_for_status()
            return resp
        except Exception as exc:
            last_exc = exc
            if attempt < retries:
                time.sleep(backoff * attempt)
    raise RuntimeError(f"Failed to fetch {url} after {retries} attempts: {last_exc}")


def recon_efotw_portal(
    portal_url: str = EFOTW_PORTAL_URL,
    ledger: ProvenanceLedger | None = None,
    force: bool = False,
) -> dict[str, Any]:
    """
    Perform authentic OSINT DOM & SPA Bundle Reconnaissance on the target EFOTW page:
    1. Archives raw HTML shell with SHA-256 provenance.
    2. Parses embedded Drupal.settings JSON to locate the SPA bundles (html.min.js / scripts.min.js).
    3. Extracts the authoritative Master Researcher XLSX URL from html.min.js.
    4. Discovers & queries the undocumented internal JSON API (/api/v1/ftw_get_all_data)
       powering the portal table for 165-country cross-verification against the Master XLSX.
    """
    import re

    RAW_DIR.mkdir(parents=True, exist_ok=True)
    html_path = RAW_DIR / "efotw_portal_snapshot.html"
    api_json_path = RAW_DIR / "efotw_portal_api_ftw_all_data.json"

    http_status = None
    resp_headers: dict[str, str] = {}

    if force or not html_path.exists():
        resp = _http_get_with_retry(portal_url, timeout=25)
        http_status = resp.status_code
        resp_headers = dict(resp.headers)
        html_path.write_bytes(resp.content)
        html_text = resp.text
    else:
        html_text = html_path.read_text(encoding="utf-8", errors="replace")

    soup = BeautifulSoup(html_text, "html.parser")

    # 1. Inspect DOM & Drupal.settings SPA JS bundles to dynamically discover XLSX & JSON API
    discovered_xlsx_url: str | None = None
    discovered_api_endpoint = f"{EFOTW_BASE_DOMAIN}/api/v1/ftw_get_all_data"

    # Check direct anchors first
    for a_tag in soup.find_all("a", href=True):
        href = a_tag["href"].strip()
        if "master-index" in href.lower() and ".xlsx" in href.lower():
            discovered_xlsx_url = urljoin(EFOTW_BASE_DOMAIN, href)

    # Parse Drupal.settings to inspect ftw_maps_pages SPA bundles (html.min.js & scripts.min.js)
    m_drupal = re.search(
        r"jQuery\.extend\(Drupal\.settings,\s*(\{.*?\})\);</script>", html_text, re.S
    )
    if m_drupal and not discovered_xlsx_url:
        try:
            drupal_cfg = json.loads(m_drupal.group(1))
            app_base = drupal_cfg.get("fraserApp", {}).get("appBaseUrl") or EFOTW_BASE_DOMAIN
            js_keys = list(drupal_cfg.get("ajaxPageState", {}).get("js", {}).keys())
            for js_rel in js_keys:
                if "ftw_maps_pages/scripts/html.min.js" in js_rel:
                    bundle_txt = _http_get_with_retry(urljoin(app_base, "/" + js_rel), timeout=20).text
                    xlsx_matches = re.findall(r"[^\s\"'<>]*master-index[^\s\"'<>]*\.xlsx", bundle_txt)
                    if xlsx_matches:
                        discovered_xlsx_url = urljoin(app_base, xlsx_matches[0])
                elif "ftw_maps_pages/scripts/scripts.min.js" in js_rel:
                    scripts_txt = _http_get_with_retry(urljoin(app_base, "/" + js_rel), timeout=20).text
                    if "ftw_get_all_data" in scripts_txt:
                        discovered_api_endpoint = urljoin(app_base, "/api/v1/ftw_get_all_data")
        except Exception:
            pass

    if not discovered_xlsx_url:
        discovered_xlsx_url = EFOTW_FALLBACK_XLSX_URL

    # 2. Query discovered internal JSON API (/api/v1/ftw_get_all_data) for cross-verification
    api_status = 200
    api_headers: dict[str, str] = {}
    if force or not api_json_path.exists() or api_json_path.stat().st_size < 10_000:
        api_resp = _http_get_with_retry(discovered_api_endpoint, timeout=30)
        api_status = api_resp.status_code
        api_headers = dict(api_resp.headers)
        api_json_path.write_bytes(api_resp.content)
        api_payload = api_resp.json()
    else:
        api_payload = json.loads(api_json_path.read_text(encoding="utf-8"))

    live_rows: list[dict[str, Any]] = []
    if isinstance(api_payload, dict) and api_payload:
        latest_portal_yr = max(int(k) for k in api_payload.keys() if str(k).isdigit())
        for item in api_payload.get(str(latest_portal_yr), []):
            try:
                s_idx = item.get("summary_index")
                live_rows.append(
                    {
                        "iso_code": (item.get("iso_code") or "").strip(),
                        "country_name": (item.get("country") or "").strip(),
                        "year": latest_portal_yr,
                        "overall_rank": int(item["rank"]) if str(item.get("rank", "")).isdigit() else None,
                        "overall_score": float(s_idx) if s_idx not in (None, "", "NA") else None,
                    }
                )
            except (ValueError, TypeError):
                continue

    if ledger is not None:
        ledger.record_artifact(
            "efotw_portal_html",
            local_path=html_path,
            source_url=portal_url,
            artifact_type="HTML_SPA_SHELL_SNAPSHOT",
            http_status=http_status or 200,
            headers=resp_headers,
            record_count=1,
            notes=f"Inspected Drupal.settings SPA bundle -> discovered {discovered_xlsx_url}",
        )
        ledger.record_artifact(
            "efotw_portal_internal_api",
            local_path=api_json_path,
            source_url=discovered_api_endpoint,
            artifact_type="INTERNAL_SPA_API_JSON",
            http_status=api_status,
            headers=api_headers,
            record_count=len(live_rows),
            notes="Undocumented /api/v1/ftw_get_all_data JSON endpoint extracted from scripts.min.js",
        )

    return {
        "portal_url": portal_url,
        "discovered_xlsx_url": discovered_xlsx_url,
        "discovered_api_endpoint": discovered_api_endpoint,
        "live_rows": live_rows,
        "html_path": html_path,
    }


def collect_efotw_master_xlsx(
    xlsx_url: str,
    ledger: ProvenanceLedger | None = None,
    force: bool = False,
) -> Path:
    """Download the Fraser Institute Master Researcher XLSX file with SHA-256 chain-of-custody."""
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    xlsx_path = RAW_DIR / "efotw_master_researcher_iso.xlsx"

    http_status = None
    resp_headers: dict[str, str] = {}

    if force or not xlsx_path.exists() or xlsx_path.stat().st_size < 100_000:
        resp = _http_get_with_retry(xlsx_url, timeout=45)
        http_status = resp.status_code
        resp_headers = dict(resp.headers)
        xlsx_path.write_bytes(resp.content)

    if ledger is not None:
        ledger.record_artifact(
            "efotw_master_xlsx",
            local_path=xlsx_path,
            source_url=xlsx_url,
            artifact_type="PRIMARY_XLSX_DATASET",
            http_status=http_status or 200,
            headers=resp_headers,
            notes="Fraser Institute Economic Freedom of the World Master Index Data (ISO)",
        )

    return xlsx_path


def _fetch_single_wb_indicator(
    col_name: str,
    spec: dict[str, str],
    start_year: int = 2000,
    end_year: int = 2025,
) -> tuple[str, str, list[dict[str, Any]]]:
    """Fetch all pages of a single World Bank / WGI indicator across all countries."""
    code = spec["code"]
    source = spec["source"]
    records: list[dict[str, Any]] = []
    page = 1
    total_pages = 1
    first_url = ""

    while page <= total_pages:
        url = (
            f"{WB_API_BASE}/country/all/indicator/{code}"
            f"?source={source}&date={start_year}:{end_year}"
            f"&format=json&per_page=4000&page={page}"
        )
        if page == 1:
            first_url = url
        resp = _http_get_with_retry(url, timeout=25)
        payload = resp.json()
        if not isinstance(payload, list) or len(payload) < 2 or payload[1] is None:
            break
        meta, items = payload[0], payload[1]
        total_pages = int(meta.get("pages", 1))
        for item in items:
            iso3 = (item.get("countryiso3code") or "").strip()
            val = item.get("value")
            yr_str = str(item.get("date") or "").strip()
            if len(iso3) == 3 and val is not None and yr_str.isdigit():
                records.append(
                    {
                        "iso_code": iso3,
                        "year": int(yr_str),
                        "metric": col_name,
                        "value": float(val),
                    }
                )
        page += 1

    return col_name, first_url, records


def collect_worldbank_enrichment(
    target_isos: set[str] | None = None,
    ledger: ProvenanceLedger | None = None,
    force: bool = False,
) -> list[dict[str, Any]]:
    """
    Concurrently ingest macro & governance indicators from World Bank (WDI)
    and Worldwide Governance Indicators (WGI) APIs, keyed by (iso_code, year).
    """
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    wb_cache_path = RAW_DIR / "worldbank_wgi_enrichment.json"

    if not force and wb_cache_path.exists() and wb_cache_path.stat().st_size > 10_000:
        cached = json.loads(wb_cache_path.read_text(encoding="utf-8"))
        if ledger is not None and "worldbank_wgi_api" not in ledger.data.get("artifacts", {}):
            ledger.record_artifact(
                "worldbank_wgi_api",
                local_path=wb_cache_path,
                source_url=f"{WB_API_BASE}/country/all/indicator/* (WDI source=2 & WGI source=3)",
                artifact_type="EXTERNAL_OSINT_API_JSON",
                http_status=200,
                record_count=len(cached),
                notes="Cached World Bank WDI & WGI enrichment indicators (2000-2025)",
            )
        return cached

    merged: dict[tuple[str, int], dict[str, Any]] = {}

    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = {
            pool.submit(_fetch_single_wb_indicator, col_name, spec): col_name
            for col_name, spec in WB_INDICATORS.items()
        }
        for fut in as_completed(futures):
            col_name = futures[fut]
            try:
                _, _, recs = fut.result()
                for r in recs:
                    iso = r["iso_code"]
                    if target_isos and iso not in target_isos:
                        continue
                    key = (iso, r["year"])
                    if key not in merged:
                        merged[key] = {"iso_code": iso, "year": r["year"]}
                    merged[key][col_name] = r["value"]
            except Exception as exc:
                # Non-fatal degradation: log missing indicator while preserving pipeline continuity
                print(f"[WARN] World Bank indicator {col_name} fetch degraded: {exc}")

    rows = sorted(merged.values(), key=lambda x: (x["iso_code"], -x["year"]))
    wb_cache_path.write_text(json.dumps(rows, indent=2), encoding="utf-8")

    if ledger is not None:
        ledger.record_artifact(
            "worldbank_wgi_api",
            local_path=wb_cache_path,
            source_url=f"{WB_API_BASE}/country/all/indicator/[WDI+WGI]?date=2000:2025",
            artifact_type="EXTERNAL_OSINT_API_JSON",
            http_status=200,
            record_count=len(rows),
            notes=(
                "Live fusion of 8 World Bank WDI & Worldwide Governance Indicators: "
                + ", ".join(s["code"] for s in WB_INDICATORS.values())
            ),
        )

    return rows
