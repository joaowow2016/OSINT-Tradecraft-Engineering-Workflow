"""
Cryptographic Chain-of-Custody & Provenance Ledger for OSINT Evidence Verification.
Every collected file and API payload is hashed (SHA-256), timestamped in UTC,
and audited against local disk artifacts and cross-source HTML/XLSX checks.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import MANIFEST_PATH, RAW_DIR


def sha256_bytes(data: bytes) -> str:
    """Compute hex-encoded SHA-256 digest of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    """Compute hex-encoded SHA-256 digest of a file on disk."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class ProvenanceLedger:
    """Manages immutable OSINT chain-of-custody records in data/raw/manifest.json."""

    def __init__(self, manifest_path: Path = MANIFEST_PATH) -> None:
        self.manifest_path = manifest_path
        self.manifest_path.parent.mkdir(parents=True, exist_ok=True)
        self._data: dict[str, Any] = self._load()

    def _load(self) -> dict[str, Any]:
        if self.manifest_path.exists():
            try:
                return json.loads(self.manifest_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                pass
        return {
            "platform": "SOVEREIGN-WATCH OSINT Pipeline",
            "schema_version": "1.0",
            "created_at_utc": utc_now_iso(),
            "updated_at_utc": utc_now_iso(),
            "artifacts": {},
            "cross_verification": {},
        }

    def save(self) -> None:
        self._data["updated_at_utc"] = utc_now_iso()
        self.manifest_path.write_text(
            json.dumps(self._data, indent=2, sort_keys=False),
            encoding="utf-8",
        )

    def record_artifact(
        self,
        artifact_id: str,
        *,
        local_path: Path,
        source_url: str,
        artifact_type: str,
        http_status: int | None = None,
        headers: dict[str, str] | None = None,
        record_count: int | None = None,
        notes: str = "",
    ) -> dict[str, Any]:
        """Hash a saved file and record its provenance entry."""
        digest = sha256_file(local_path)
        size_bytes = local_path.stat().st_size
        rel_path = str(local_path.relative_to(RAW_DIR.parent.parent))
        hdrs = headers or {}
        entry = {
            "artifact_id": artifact_id,
            "artifact_type": artifact_type,
            "source_url": source_url,
            "local_path": rel_path,
            "sha256": digest,
            "size_bytes": size_bytes,
            "retrieved_at_utc": utc_now_iso(),
            "http_status": http_status,
            "etag": hdrs.get("ETag") or hdrs.get("etag"),
            "last_modified": hdrs.get("Last-Modified") or hdrs.get("last-modified"),
            "content_type": hdrs.get("Content-Type") or hdrs.get("content-type"),
            "record_count": record_count,
            "notes": notes,
        }
        self._data["artifacts"][artifact_id] = entry
        self.save()
        return entry

    def record_cross_verification(self, report: dict[str, Any]) -> None:
        """Store HTML-vs-XLSX cross-verification audit results."""
        report["verified_at_utc"] = utc_now_iso()
        self._data["cross_verification"] = report
        self.save()

    def verify_all_artifacts(self) -> dict[str, Any]:
        """Re-hash every artifact on disk and confirm zero tampering or bit-rot."""
        results = []
        all_valid = True
        base_root = RAW_DIR.parent.parent
        for aid, meta in self._data.get("artifacts", {}).items():
            fpath = base_root / meta["local_path"]
            if not fpath.exists():
                all_valid = False
                results.append(
                    {
                        "artifact_id": aid,
                        "status": "MISSING",
                        "expected_sha256": meta["sha256"],
                        "actual_sha256": None,
                        "size_bytes": 0,
                    }
                )
                continue
            actual_hash = sha256_file(fpath)
            matched = actual_hash == meta["sha256"]
            if not matched:
                all_valid = False
            results.append(
                {
                    "artifact_id": aid,
                    "status": "VERIFIED" if matched else "HASH_MISMATCH",
                    "source_url": meta["source_url"],
                    "local_path": meta["local_path"],
                    "expected_sha256": meta["sha256"],
                    "actual_sha256": actual_hash,
                    "size_bytes": fpath.stat().st_size,
                    "retrieved_at_utc": meta.get("retrieved_at_utc"),
                    "record_count": meta.get("record_count"),
                }
            )
        return {
            "overall_status": "PASS" if (all_valid and len(results) > 0) else "FAIL",
            "checked_at_utc": utc_now_iso(),
            "artifact_count": len(results),
            "artifacts": results,
            "cross_verification": self._data.get("cross_verification", {}),
        }

    @property
    def data(self) -> dict[str, Any]:
        return self._data


def cross_verify_portal_vs_master(
    portal_rows: list[dict[str, Any]],
    master_latest_by_iso: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """
    OSINT Cross-Verification Check:
    Compares the live JSON feed (/api/v1/ftw_get_all_data) serving efotw.org against
    the Fraser Institute researcher master XLSX ('EFW Ratings' sheet) across all 165
    ISO-3 jurisdictions to detect silent revisions, API drift, or upstream tampering.
    """
    checked = 0
    matched = 0
    discrepancies: list[dict[str, Any]] = []

    for row in portal_rows:
        iso = (row.get("iso_code") or "").strip()
        cname = (row.get("country_name") or "").strip()
        portal_score = row.get("overall_score")
        portal_year = row.get("year")
        if not iso or portal_score is None:
            continue
        master = master_latest_by_iso.get(iso)
        if not master or master.get("year") != portal_year:
            continue
        checked += 1
        m_score = master.get("efw_score")
        if m_score is not None and abs(float(portal_score) - float(m_score)) <= 0.025:
            matched += 1
        else:
            discrepancies.append(
                {
                    "iso_code": iso,
                    "country_name": cname,
                    "year": portal_year,
                    "portal_api_score": portal_score,
                    "master_xlsx_score": m_score,
                    "delta": round(float(portal_score) - float(m_score or 0.0), 4),
                }
            )

    agreement_pct = round((matched / checked) * 100.0, 2) if checked > 0 else 0.0
    return {
        "status": "VERIFIED" if (checked >= 150 and agreement_pct >= 98.0) else "WARNING",
        "portal_rows_scraped": len(portal_rows),
        "countries_cross_checked": checked,
        "exact_matches": matched,
        "agreement_pct": agreement_pct,
        "discrepancies": discrepancies[:10],
    }
