"""
Automated OSINT Integrity, Analytics & API Verification Suite for SOVEREIGN-WATCH.
"""

from __future__ import annotations

import sqlite3
import unittest

from efotw_osint.config import DB_PATH
from efotw_osint.dossier import build_country_dossier_payload, format_dossier_markdown
from efotw_osint.provenance import ProvenanceLedger
from efotw_osint.server import (
    get_alerts_payload,
    get_overview_payload,
    get_watchlist_payload,
)


class TestSovereignWatchOSINT(unittest.TestCase):
    def test_provenance_sha256_and_portal_cross_verification(self) -> None:
        ledger = ProvenanceLedger()
        audit = ledger.verify_all_artifacts()
        self.assertEqual(audit["overall_status"], "PASS")
        self.assertGreaterEqual(audit["artifact_count"], 4)

        xver = audit["cross_verification"]
        self.assertEqual(xver["status"], "VERIFIED")
        self.assertEqual(xver["countries_cross_checked"], 165)
        self.assertEqual(xver["exact_matches"], 165)
        self.assertEqual(xver["agreement_pct"], 100.0)

    def test_entity_resolution_100_percent_historical(self) -> None:
        conn = sqlite3.connect(str(DB_PATH))
        try:
            total = conn.execute("SELECT COUNT(*) FROM efw_historical").fetchone()[0]
            unresolved = conn.execute(
                "SELECT COUNT(*) FROM efw_historical WHERE iso_code IS NULL"
            ).fetchone()[0]
            self.assertEqual(total, 458)
            self.assertEqual(unresolved, 0, "All 1950-1965 entities must resolve to ISO-3")
        finally:
            conn.close()

    def test_overview_and_watchlist_integrity(self) -> None:
        ov = get_overview_payload(DB_PATH)
        self.assertEqual(ov["jurisdictions_monitored"], 165)
        self.assertEqual(ov["latest_year"], 2024)
        self.assertGreater(ov["active_alerts_count"], 20)

        wl = get_watchlist_payload({}, DB_PATH)
        self.assertEqual(wl["count"], 165)
        for item in wl["items"]:
            self.assertGreaterEqual(item["composite_risk_score"], 0.0)
            self.assertLessEqual(item["composite_risk_score"], 100.0)
            self.assertIn(
                item["threat_tier"],
                {"CRITICAL", "HIGH", "ELEVATED", "GUARDED", "LOW"},
            )
            self.assertIsNotNone(item["regime_archetype"])

    def test_alerts_and_country_dossier(self) -> None:
        alerts = get_alerts_payload({"year": ["2024"], "severity": ["CRITICAL"]}, DB_PATH)
        self.assertGreater(alerts["count"], 5)

        ven = build_country_dossier_payload("VEN", DB_PATH)
        self.assertEqual(ven["iso_code"], "VEN")
        self.assertEqual(ven["summary"]["threat_tier"], "CRITICAL")
        # Verify 1950-1965 historical entity resolution merged into Venezuela's timeline
        years = [row["year"] for row in ven["timeline"]]
        self.assertLessEqual(min(years), 1965)
        self.assertEqual(max(years), 2024)

        md = format_dossier_markdown(ven)
        self.assertIn("OSINT SOVEREIGN INTELLIGENCE DOSSIER", md)
        self.assertIn("VENEZUELA", md.upper())


if __name__ == "__main__":
    unittest.main()
