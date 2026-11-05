"""
Rich + Typer Command-Line Intelligence Interface for SOVEREIGN-WATCH.
"""

from __future__ import annotations

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .config import DB_PATH
from .dossier import (
    build_country_dossier_payload,
    export_country_dossier,
    generate_global_sitrep_markdown,
)
from .pipeline import run_full_osint_pipeline
from .provenance import ProvenanceLedger
from .server import get_alerts_payload, get_watchlist_payload, run_server

app = typer.Typer(
    name="sovereign-watch",
    help="SOVEREIGN-WATCH // OSINT Geopolitical Risk & Early-Warning Toolkit (EFOTW × World Bank/WGI)",
    add_completion=False,
)
console = Console()

TIER_STYLE = {
    "CRITICAL": "bold red",
    "HIGH": "bold dark_orange",
    "ELEVATED": "bold yellow",
    "GUARDED": "cyan",
    "LOW": "green",
}


@app.command("ingest")
def cmd_ingest(
    enrich_wb: bool = typer.Option(True, "--wb/--no-wb", help="Fuse live World Bank WDI & WGI feeds"),
    force: bool = typer.Option(False, "--force", help="Force re-download of upstream raw sources"),
) -> None:
    """Execute end-to-end OSINT recon, collection, SHA-256 hashing, WGI fusion & risk modeling."""
    console.print(
        Panel.fit(
            "[bold cyan]SOVEREIGN-WATCH OSINT INGESTION PIPELINE[/bold cyan]\n"
            "Target: efotw.org SPA Recon + Fraser Master XLSX + World Bank/WGI APIs",
            border_style="cyan",
        )
    )
    summary = run_full_osint_pipeline(enrich_worldbank=enrich_wb, force_refresh=force)
    xv = summary["cross_verification"]
    t = Table(title="Ingestion & Intelligence Summary", box=box.SIMPLE_HEAVY)
    t.add_column("Metric", style="cyan")
    t.add_column("Value", style="bold white")
    t.add_row("Latest Assessment Year", str(summary["latest_year"]))
    t.add_row("Jurisdictions Monitored", str(summary["jurisdictions_monitored"]))
    t.add_row("1950–1965 Entity Resolution", f"{summary['historical_resolved_pct']}%")
    t.add_row(
        "Portal SPA API vs XLSX Cross-Audit",
        f"[{ 'green' if xv['status']=='VERIFIED' else 'yellow' }]{xv['status']} ({xv['exact_matches']}/{xv['countries_cross_checked']} = {xv['agreement_pct']}%)[/]",
    )
    t.add_row("Critical / High Risk Regimes", f"{summary['critical_regimes_count']} Critical / {summary['high_regimes_count']} High")
    t.add_row("Active Early-Warning Alerts", str(summary["active_alerts_latest_year"]))
    for tbl, cnt in summary["table_counts"].items():
        t.add_row(f"SQLite Table `{tbl}`", f"{cnt:,} rows")
    console.print(t)


@app.command("verify")
def cmd_verify() -> None:
    """Audit SHA-256 cryptographic chain-of-custody for all collected OSINT artifacts."""
    ledger = ProvenanceLedger()
    audit = ledger.verify_all_artifacts()
    xv = audit.get("cross_verification", {})

    status_color = "green" if audit["overall_status"] == "PASS" else "red"
    console.print(
        Panel.fit(
            f"[bold {status_color}]CHAIN-OF-CUSTODY STATUS: {audit['overall_status']}[/bold {status_color}]  "
            f"(Checked UTC: {audit['checked_at_utc']})\n"
            f"Portal Internal API vs. Master XLSX Cross-Verification: "
            f"[bold green]{xv.get('exact_matches', 0)}/{xv.get('countries_cross_checked', 0)} "
            f"({xv.get('agreement_pct', 0)}% Agreement)[/bold green]",
            border_style=status_color,
        )
    )

    t = Table(box=box.ROUNDED, show_lines=False)
    t.add_column("Artifact ID", style="bold cyan")
    t.add_column("Status", style="bold green")
    t.add_column("SHA-256 Digest")
    t.add_column("Size (KB)", justify="right")
    t.add_column("Records", justify="right")
    t.add_column("Retrieved UTC")

    for a in audit["artifacts"]:
        st = a["status"]
        col = "green" if st == "VERIFIED" else "red"
        t.add_row(
            a["artifact_id"],
            f"[{col}]{st}[/{col}]",
            (a["actual_sha256"] or "MISSING")[:32] + "…",
            f"{a['size_bytes'] / 1024:.1f}",
            str(a.get("record_count") or "—"),
            str(a.get("retrieved_at_utc") or "—"),
        )
    console.print(t)


@app.command("watchlist")
def cmd_watchlist(
    limit: int = typer.Option(25, "--limit", "-n", help="Number of jurisdictions to display"),
    tier: str = typer.Option("ALL", "--tier", help="Filter by CRITICAL, HIGH, ELEVATED, GUARDED, LOW"),
    region: str = typer.Option("ALL", "--region", help="Filter by World Bank region"),
    sort_decay: bool = typer.Option(False, "--decay", help="Sort by fastest 5-year panel deterioration"),
) -> None:
    """Display the Sovereign Geopolitical Risk Watchlist in the terminal."""
    resp = get_watchlist_payload({"tier": [tier], "region": [region]}, db_path=DB_PATH)
    items = resp["items"]
    if sort_decay:
        items = [x for x in items if x.get("delta_5y") is not None]
        items.sort(key=lambda x: float(x["delta_5y"]))
    items = items[:limit]

    title = (
        f"SOVEREIGN-WATCH // Fastest 5Y Deterioration ({resp['year']})"
        if sort_decay
        else f"SOVEREIGN-WATCH // Geopolitical Risk Watchlist ({resp['year']}, Top {len(items)})"
    )
    t = Table(title=title, box=box.SIMPLE_HEAVY)
    t.add_column("#", justify="right", style="dim")
    t.add_column("ISO", style="bold cyan")
    t.add_column("Jurisdiction", style="bold white")
    t.add_column("Tier")
    t.add_column("Risk", justify="right")
    t.add_column("EFW", justify="right")
    t.add_column("5Y Δ", justify="right")
    t.add_column("Inst.", justify="right")
    t.add_column("Mon.", justify="right")
    t.add_column("Cap.Siege", justify="right")
    t.add_column("Alerts", justify="right")
    t.add_column("ML Regime Archetype", style="dim")

    for r in items:
        tr = r["threat_tier"]
        st = TIER_STYLE.get(tr, "white")
        d5 = r.get("delta_5y")
        d5_str = "—" if d5 is None else f"[{'red' if d5 <= -0.3 else 'green' if d5 >= 0.2 else 'white'}]{d5:+.2f}[/]"
        t.add_row(
            str(r.get("risk_rank") or "—"),
            r["iso_code"],
            r["country_name"],
            f"[{st}]{tr}[/{st}]",
            f"{r['composite_risk_score']:.1f}",
            f"{r['efw_score']:.2f}" if r.get("efw_score") is not None else "—",
            d5_str,
            f"{r['inst_decay_risk']:.1f}",
            f"{r['monetary_stress_risk']:.1f}",
            f"{r['capital_siege_risk']:.1f}",
            str(r.get("alert_count", 0)),
            str(r.get("regime_archetype") or ""),
        )
    console.print(t)


@app.command("alerts")
def cmd_alerts(
    severity: str = typer.Option("ALL", "--severity", "-s", help="CRITICAL, HIGH, ELEVATED, or ALL"),
    alert_type: str = typer.Option("ALL", "--type", "-t", help="Filter by alert typology"),
    year: str = typer.Option("2024", "--year", "-y", help="Assessment cycle year"),
    limit: int = typer.Option(25, "--limit", "-n", help="Max alerts to display"),
) -> None:
    """List structured early-warning intelligence alerts."""
    resp = get_alerts_payload(
        {"year": [year], "severity": [severity], "alert_type": [alert_type]},
        db_path=DB_PATH,
    )
    items = resp["items"][:limit]
    t = Table(title=f"Early-Warning Intelligence Feed ({len(items)} of {resp['count']})", box=box.SIMPLE_HEAVY)
    t.add_column("Sev")
    t.add_column("ISO", style="bold cyan")
    t.add_column("Typology", style="magenta")
    t.add_column("Headline & Quantitative Trigger Evidence")

    for a in items:
        sev = a["severity"]
        st = TIER_STYLE.get(sev, "white")
        t.add_row(
            f"[{st}]{sev}[/{st}]",
            a["iso_code"],
            a["alert_type"],
            f"[bold]{a['headline']}[/bold]\n[dim]{a['evidence_summary']}[/dim]",
        )
    console.print(t)


@app.command("dossier")
def cmd_dossier(
    target: str = typer.Argument(..., help="ISO-3 code or Country Name (e.g. VEN, BRA, Myanmar)"),
    export: bool = typer.Option(True, "--export/--no-export", help="Save Markdown brief to reports/"),
) -> None:
    """Generate a deep-dive Country Intelligence Dossier."""
    payload = build_country_dossier_payload(target, db_path=DB_PATH)
    s = payload["summary"]
    tr = s["threat_tier"]
    st = TIER_STYLE.get(tr, "white")

    console.print(
        Panel(
            f"[bold white]{payload['country_name'].upper()} ({payload['iso_code']})[/bold white] — "
            f"[{st}]{tr} THREAT TIER ({s['composite_risk_score']:.2f}/100, Global Risk #{s['risk_rank']})[/{st}]\n"
            f"EFOTW Score: [bold]{s['efw_score']:.2f}/10[/bold] (Rank #{int(s['efw_rank']) if s.get('efw_rank') else '—'})  |  "
            f"5Y Panel Velocity: [bold]{s['delta_5y']:+.3f}[/bold] ({s['z_velocity_5y']:+.2f}σ)  |  "
            f"Archetype: [cyan]{s['regime_archetype']}[/cyan]",
            title="OSINT COUNTRY INTELLIGENCE DOSSIER",
            border_style="cyan",
        )
    )

    vt = Table(title="Top Acute Sub-Indicator Vulnerabilities", box=box.SIMPLE)
    vt.add_column("Sub-Indicator", style="bold")
    vt.add_column("Domain", style="dim")
    vt.add_column("Rating (0–10)", justify="right")
    vt.add_column("5Y Shift", justify="right")
    vt.add_column("Vulnerability", justify="right")

    for item in [x for x in payload["sub_indicators"] if x["score_10"] is not None][:8]:
        d5 = item["delta_5y"]
        vt.add_row(
            item["label"],
            item["domain"],
            f"{item['score_10']:.2f}",
            f"{d5:+.2f}" if d5 is not None else "—",
            f"{item['vulnerability_100']:.0f}%",
        )
    console.print(vt)

    if export:
        out = export_country_dossier(payload["iso_code"], db_path=DB_PATH)
        console.print(f"[bold green]✓ Exported standalone intelligence dossier:[/bold green] {out}")


@app.command("sitrep")
def cmd_sitrep() -> None:
    """Export the Global Geopolitical Risk & Early-Warning SITREP Markdown brief."""
    out = generate_global_sitrep_markdown(db_path=DB_PATH)
    console.print(f"[bold green]✓ Global Threat SITREP written to:[/bold green] {out}")


@app.command("serve")
def cmd_serve(
    host: str = typer.Option("0.0.0.0", "--host", help="Bind host (0.0.0.0 for live preview)"),
    port: int = typer.Option(8000, "--port", "-p", help="TCP port"),
) -> None:
    """Launch the interactive SOVEREIGN-WATCH Analyst Web Workbench."""
    run_server(host=host, port=port, db_path=DB_PATH)


if __name__ == "__main__":
    app()
