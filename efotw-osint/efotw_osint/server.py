"""
Multi-Threaded OSINT REST API & Analyst Web Workbench HTTP Server.
Binds to 0.0.0.0:8000 with zero host-allowlist restrictions so it runs cleanly
in reverse-proxied live preview environments as well as local workstations.
"""

from __future__ import annotations

import gzip
import json
import mimetypes
import os
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

import plotly

from .config import DB_PATH, STATIC_DIR
from .database import get_connection
from .dossier import build_country_dossier_payload, format_dossier_markdown
from .provenance import ProvenanceLedger

PLOTLY_JS_PATH = Path(plotly.__file__).resolve().parent / "package_data" / "plotly.min.js"


def _rows_to_list(rows: list[Any]) -> list[dict[str, Any]]:
    return [dict(r) for r in rows]


def get_overview_payload(db_path: Path = DB_PATH) -> dict[str, Any]:
    conn = get_connection(db_path)
    try:
        years = [
            int(r["year"])
            for r in conn.execute(
                "SELECT DISTINCT year FROM sovereign_risk_scores ORDER BY year DESC"
            ).fetchall()
        ]
        latest_year = years[0] if years else 2024

        tier_counts = {
            r["threat_tier"]: int(r["cnt"])
            for r in conn.execute(
                """
                SELECT threat_tier, COUNT(*) AS cnt
                FROM sovereign_risk_scores
                WHERE year = ?
                GROUP BY threat_tier
                """,
                (latest_year,),
            ).fetchall()
        }

        archetype_counts = _rows_to_list(
            conn.execute(
                """
                SELECT regime_archetype,
                       COUNT(*) AS count,
                       ROUND(AVG(composite_risk_score), 2) AS avg_risk,
                       ROUND(AVG(efw_score), 2) AS avg_efw
                FROM sovereign_risk_scores
                WHERE year = ?
                GROUP BY regime_archetype
                ORDER BY avg_risk DESC
                """,
                (latest_year,),
            ).fetchall()
        )

        regional_summary = _rows_to_list(
            conn.execute(
                """
                SELECT COALESCE(wb_region, 'Unclassified') AS wb_region,
                       COUNT(*) AS countries,
                       ROUND(AVG(composite_risk_score), 2) AS avg_risk,
                       ROUND(AVG(efw_score), 2) AS avg_efw,
                       ROUND(AVG(delta_5y), 3) AS avg_delta_5y,
                       SUM(CASE WHEN threat_tier IN ('CRITICAL', 'HIGH') THEN 1 ELSE 0 END) AS high_crit_count
                FROM sovereign_risk_scores
                WHERE year = ?
                GROUP BY COALESCE(wb_region, 'Unclassified')
                ORDER BY avg_risk DESC
                """,
                (latest_year,),
            ).fetchall()
        )

        fastest_decay = _rows_to_list(
            conn.execute(
                """
                SELECT iso_code, country_name, wb_region, composite_risk_score, threat_tier,
                       efw_score, delta_5y, z_velocity_5y, worst_area_5y_drop
                FROM sovereign_risk_scores
                WHERE year = ? AND delta_5y IS NOT NULL
                ORDER BY delta_5y ASC
                LIMIT 15
                """,
                (latest_year,),
            ).fetchall()
        )

        fastest_reform = _rows_to_list(
            conn.execute(
                """
                SELECT iso_code, country_name, wb_region, composite_risk_score, threat_tier,
                       efw_score, delta_5y, z_velocity_5y
                FROM sovereign_risk_scores
                WHERE year = ? AND delta_5y IS NOT NULL AND composite_risk_score < 48.0
                ORDER BY delta_5y DESC
                LIMIT 10
                """,
                (latest_year,),
            ).fetchall()
        )

        alert_summary = _rows_to_list(
            conn.execute(
                """
                SELECT alert_type, severity, COUNT(*) AS count
                FROM early_warning_alerts
                WHERE year = ?
                GROUP BY alert_type, severity
                ORDER BY count DESC
                """,
                (latest_year,),
            ).fetchall()
        )

        total_alerts_latest = sum(int(x["count"]) for x in alert_summary)
        crit_alerts_latest = sum(
            int(x["count"]) for x in alert_summary if x["severity"] == "CRITICAL"
        )

        ledger = ProvenanceLedger()
        audit = ledger.verify_all_artifacts()

        return {
            "latest_year": latest_year,
            "available_years": years,
            "jurisdictions_monitored": sum(tier_counts.values()),
            "tier_counts": tier_counts,
            "critical_and_high_count": tier_counts.get("CRITICAL", 0) + tier_counts.get("HIGH", 0),
            "active_alerts_count": total_alerts_latest,
            "critical_alerts_count": crit_alerts_latest,
            "archetype_summary": archetype_counts,
            "regional_summary": regional_summary,
            "fastest_decay": fastest_decay,
            "fastest_reform": fastest_reform,
            "alert_summary": alert_summary,
            "provenance_status": {
                "overall_status": audit["overall_status"],
                "artifact_count": audit["artifact_count"],
                "cross_verification": audit.get("cross_verification", {}),
            },
        }
    finally:
        conn.close()


def get_watchlist_payload(params: dict[str, list[str]], db_path: Path = DB_PATH) -> dict[str, Any]:
    conn = get_connection(db_path)
    try:
        latest_year = int(
            conn.execute("SELECT MAX(year) AS y FROM sovereign_risk_scores").fetchone()["y"]
        )
        year = int(params.get("year", [str(latest_year)])[0])
        region = (params.get("region", [""])[0] or "").strip()
        tier = (params.get("tier", [""])[0] or "").strip()
        archetype = (params.get("archetype", [""])[0] or "").strip()
        q = (params.get("q", [""])[0] or "").strip()

        clauses = ["year = ?"]
        sql_args: list[Any] = [year]

        if region and region != "ALL":
            clauses.append("COALESCE(wb_region, 'Unclassified') = ?")
            sql_args.append(region)
        if tier and tier != "ALL":
            clauses.append("threat_tier = ?")
            sql_args.append(tier)
        if archetype and archetype != "ALL":
            clauses.append("regime_archetype = ?")
            sql_args.append(archetype)
        if q:
            clauses.append("(LOWER(country_name) LIKE LOWER(?) OR LOWER(iso_code) LIKE LOWER(?))")
            sql_args.extend([f"%{q}%", f"%{q}%"])

        where_sql = " AND ".join(clauses)
        rows = _rows_to_list(
            conn.execute(
                f"""
                SELECT * FROM sovereign_risk_scores
                WHERE {where_sql}
                ORDER BY composite_risk_score DESC
                """,
                sql_args,
            ).fetchall()
        )

        # Attach alert counts per ISO for that year
        alert_counts = {
            r["iso_code"]: int(r["cnt"])
            for r in conn.execute(
                "SELECT iso_code, COUNT(*) AS cnt FROM early_warning_alerts WHERE year = ? GROUP BY iso_code",
                (year,),
            ).fetchall()
        }
        for row in rows:
            row["alert_count"] = alert_counts.get(row["iso_code"], 0)

        return {"year": year, "count": len(rows), "items": rows}
    finally:
        conn.close()


def get_alerts_payload(params: dict[str, list[str]], db_path: Path = DB_PATH) -> dict[str, Any]:
    conn = get_connection(db_path)
    try:
        latest_year = int(
            conn.execute("SELECT MAX(year) AS y FROM sovereign_risk_scores").fetchone()["y"]
        )
        year_param = (params.get("year", [str(latest_year)])[0] or "").strip()
        severity = (params.get("severity", [""])[0] or "").strip()
        alert_type = (params.get("alert_type", [""])[0] or "").strip()
        region = (params.get("region", [""])[0] or "").strip()
        q = (params.get("q", [""])[0] or "").strip()

        clauses: list[str] = []
        args: list[Any] = []

        if year_param and year_param != "ALL":
            clauses.append("year = ?")
            args.append(int(year_param))
        if severity and severity != "ALL":
            clauses.append("severity = ?")
            args.append(severity)
        if alert_type and alert_type != "ALL":
            clauses.append("alert_type = ?")
            args.append(alert_type)
        if region and region != "ALL":
            clauses.append("wb_region = ?")
            args.append(region)
        if q:
            clauses.append(
                "(LOWER(country_name) LIKE LOWER(?) OR LOWER(iso_code) LIKE LOWER(?) OR LOWER(headline) LIKE LOWER(?))"
            )
            args.extend([f"%{q}%", f"%{q}%", f"%{q}%"])

        where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        raw_rows = _rows_to_list(
            conn.execute(
                f"""
                SELECT * FROM early_warning_alerts
                {where_sql}
                ORDER BY year DESC,
                         CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'ELEVATED' THEN 2 ELSE 3 END,
                         composite_risk_score DESC
                """,
                args,
            ).fetchall()
        )
        for r in raw_rows:
            try:
                r["trigger_metrics"] = json.loads(r.pop("trigger_metrics_json", "{}") or "{}")
            except json.JSONDecodeError:
                r["trigger_metrics"] = {}

        alert_years = [
            int(r["year"])
            for r in conn.execute(
                "SELECT DISTINCT year FROM early_warning_alerts ORDER BY year DESC"
            ).fetchall()
        ]
        return {"count": len(raw_rows), "available_years": alert_years, "items": raw_rows}
    finally:
        conn.close()


class SovereignWatchHTTPHandler(BaseHTTPRequestHandler):
    """Thread-safe HTTP handler serving REST JSON endpoints + SPA workbench."""

    db_path: Path = DB_PATH

    def log_message(self, fmt: str, *args: Any) -> None:
        # Clean concise server log
        print(f"[HTTP] {self.address_string()} - {fmt % args}")

    def _send_bytes(
        self,
        body: bytes,
        *,
        status: int = 200,
        content_type: str = "application/json; charset=utf-8",
        extra_headers: dict[str, str] | None = None,
        compress: bool = True,
    ) -> None:
        accept_enc = self.headers.get("Accept-Encoding", "")
        if compress and len(body) > 1024 and "gzip" in accept_enc:
            body = gzip.compress(body, compresslevel=5)
            is_gzip = True
        else:
            is_gzip = False

        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        if is_gzip:
            self.send_header("Content-Encoding", "gzip")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, payload: Any, status: int = 200) -> None:
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._send_bytes(
            raw,
            status=status,
            content_type="application/json; charset=utf-8",
            extra_headers={"Cache-Control": "no-cache"},
        )

    def do_OPTIONS(self) -> None:
        self._send_bytes(b"", status=204, content_type="text/plain", compress=False)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        params = parse_qs(parsed.query)

        try:
            # --- REST API Routes ---
            if path == "/api/health":
                self._send_json({"status": "ok", "db_exists": self.db_path.exists()})
                return

            if path == "/api/overview":
                self._send_json(get_overview_payload(self.db_path))
                return

            if path == "/api/watchlist":
                self._send_json(get_watchlist_payload(params, self.db_path))
                return

            if path == "/api/alerts":
                self._send_json(get_alerts_payload(params, self.db_path))
                return

            if path == "/api/provenance":
                ledger = ProvenanceLedger()
                self._send_json(ledger.verify_all_artifacts())
                return

            if path.startswith("/api/country/"):
                target = path[len("/api/country/") :].strip("/")
                payload = build_country_dossier_payload(target, db_path=self.db_path)
                self._send_json(payload)
                return

            if path.startswith("/api/dossier/"):
                target = path[len("/api/dossier/") :].strip("/")
                if target.endswith(".md"):
                    target = target[:-3]
                payload = build_country_dossier_payload(target, db_path=self.db_path)
                md_bytes = format_dossier_markdown(payload).encode("utf-8")
                fname = f"OSINT_Dossier_{payload['iso_code']}_{payload['latest_year']}.md"
                self._send_bytes(
                    md_bytes,
                    status=200,
                    content_type="text/markdown; charset=utf-8",
                    extra_headers={
                        "Content-Disposition": f'attachment; filename="{fname}"',
                    },
                )
                return

            # --- Local Self-Hosted Plotly Bundle (Zero CDN Dependency) ---
            if path == "/vendor/plotly.min.js":
                if PLOTLY_JS_PATH.exists():
                    self._send_bytes(
                        PLOTLY_JS_PATH.read_bytes(),
                        status=200,
                        content_type="application/javascript; charset=utf-8",
                        extra_headers={"Cache-Control": "public, max-age=86400"},
                    )
                    return

            # --- Static Analyst Workbench Assets ---
            if path in ("/", "/index.html"):
                target_file = STATIC_DIR / "index.html"
            else:
                rel = path.lstrip("/")
                target_file = (STATIC_DIR / rel).resolve()
                if not str(target_file).startswith(str(STATIC_DIR.resolve())):
                    self._send_json({"error": "Forbidden"}, status=403)
                    return

            if target_file.exists() and target_file.is_file():
                ctype, _ = mimetypes.guess_type(str(target_file))
                self._send_bytes(
                    target_file.read_bytes(),
                    status=200,
                    content_type=ctype or "application/octet-stream",
                    extra_headers={"Cache-Control": "no-cache"},
                )
                return

            self._send_json({"error": f"Route not found: {path}"}, status=404)

        except ValueError as ve:
            self._send_json({"error": str(ve)}, status=404)
        except Exception as exc:
            traceback.print_exc()
            self._send_json({"error": f"Internal server error: {exc}"}, status=500)


def run_server(host: str = "0.0.0.0", port: int = 8000, db_path: Path = DB_PATH) -> None:
    """Start multi-threaded SOVEREIGN-WATCH HTTP server bound to 0.0.0.0."""
    if not db_path.exists():
        print("[SOVEREIGN-WATCH] Database not found on fresh clone — bootstrapping OSINT pipeline...")
        from .pipeline import run_full_osint_pipeline

        run_full_osint_pipeline(db_path=db_path, enrich_worldbank=True)

    SovereignWatchHTTPHandler.db_path = db_path
    ThreadingHTTPServer.allow_reuse_address = True
    httpd = ThreadingHTTPServer((host, port), SovereignWatchHTTPHandler)
    print(f"[SOVEREIGN-WATCH] OSINT Analyst Workbench listening on http://{host}:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[SOVEREIGN-WATCH] Shutting down server...")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    port_env = int(os.environ.get("PORT", "8000"))
    run_server(host="0.0.0.0", port=port_env)
