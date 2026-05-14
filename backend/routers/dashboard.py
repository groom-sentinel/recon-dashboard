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
    vuln_critical: int


class PortExposureItem(BaseModel):
    port: int
    assets: int


@router.get("/summary", response_model=SummaryResponse)
async def get_summary():
    with engine.connect() as conn:
        total_assets = conn.execute(
            text("SELECT COUNT(*) FROM assets")
        ).scalar() or 0

        # PDF: 위험 자산 = critical + high 만 DISTINCT
        risky_assets = conn.execute(
            text("""
                SELECT COUNT(DISTINCT asset_id)
                FROM vulnerabilities
                WHERE severity IN ('critical', 'high')
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
                WHERE severity = 'high' AND no_vuln_found = 0
            """)
        ).scalar() or 0

        vuln_critical = conn.execute(
            text("""
                SELECT COUNT(*) FROM vulnerabilities
                WHERE severity = 'critical' AND no_vuln_found = 0
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
        vuln_critical=vuln_critical,
    )


@router.get("/port-exposure", response_model=List[PortExposureItem])
async def port_exposure(limit: int = 20):
    lim = max(1, min(limit, 100))
    with engine.connect() as conn:
        rows = conn.execute(
            text("""
                SELECT port, COUNT(DISTINCT asset_id) AS asset_cnt
                FROM service_scans
                GROUP BY port
                ORDER BY asset_cnt DESC, port ASC
                LIMIT :lim
            """),
            {"lim": lim},
        ).fetchall()
    return [PortExposureItem(port=int(r[0]), assets=int(r[1])) for r in rows]
