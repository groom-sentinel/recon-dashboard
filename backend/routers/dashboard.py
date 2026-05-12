# routers/dashboard.py
from fastapi import APIRouter
from pydantic import BaseModel
from typing import List

from sqlalchemy import text

from db import engine

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


class AssetSummary(BaseModel):
    name:        str
    ports_count: int


class SummaryResponse(BaseModel):
    total_assets:  int
    risky_assets:  int
    critical_cves: int
    assets:        List[AssetSummary]
    vuln_low:      int
    vuln_medium:   int
    vuln_high:     int


@router.get("/summary", response_model=SummaryResponse)
async def get_summary():
    with engine.connect() as conn:
        total_assets = conn.execute(
            text("SELECT COUNT(*) FROM assets")
        ).scalar() or 0

        risky_assets = conn.execute(
            text("""
                SELECT COUNT(DISTINCT asset_id)
                FROM vulnerabilities
                WHERE severity IN ('critical', 'high', 'medium')
                  AND no_vuln_found = 0
            """)
        ).scalar() or 0

        critical_cves = conn.execute(
            text("""
                SELECT COUNT(*)
                FROM vulnerabilities
                WHERE severity = 'critical' AND no_vuln_found = 0
            """)
        ).scalar() or 0

        vuln_low = conn.execute(
            text("""
                SELECT COUNT(*) FROM vulnerabilities
                WHERE severity = 'low' AND no_vuln_found = 0
            """)
        ).scalar() or 0

        vuln_medium = conn.execute(
            text("""
                SELECT COUNT(*) FROM vulnerabilities
                WHERE severity = 'medium' AND no_vuln_found = 0
            """)
        ).scalar() or 0

        vuln_high = conn.execute(
            text("""
                SELECT COUNT(*) FROM vulnerabilities
                WHERE severity IN ('high', 'critical') AND no_vuln_found = 0
            """)
        ).scalar() or 0

        asset_rows = conn.execute(
            text("""
                SELECT a.domain, a.asset_key, COUNT(s.scan_id) AS ports_count
                FROM assets a
                LEFT JOIN service_scans s ON s.asset_id = a.asset_id
                GROUP BY a.asset_id, a.domain, a.asset_key
                ORDER BY a.ingested_at DESC
                LIMIT 100
            """)
        ).fetchall()

    assets_list = [
        AssetSummary(
            name=row[0] or row[1],
            ports_count=row[2],
        )
        for row in asset_rows
    ]

    return SummaryResponse(
        total_assets=total_assets,
        risky_assets=risky_assets,
        critical_cves=critical_cves,
        assets=assets_list,
        vuln_low=vuln_low,
        vuln_medium=vuln_medium,
        vuln_high=vuln_high,
    )
