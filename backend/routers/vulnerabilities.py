"""Vulnerability rows and lightweight aggregates for charts."""

from __future__ import annotations

import json
from typing import Any, List, Optional

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field
from sqlalchemy import text

from db import engine

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])


class VulnerabilityOut(BaseModel):
    vuln_id: int
    asset_id: int
    domain: Optional[str] = None
    ip: str
    port: int
    service: Optional[str] = None
    name: str
    severity: str
    cve_ids: List[str] = Field(default_factory=list)
    cvss_score: Optional[float] = None
    cvss_severity: Optional[str] = None
    epss: Optional[float] = None
    source: str
    module: Optional[str] = None
    matched_url: Optional[str] = None
    no_vuln_found: bool


class SeverityCount(BaseModel):
    severity: str
    count: int


class SourceCount(BaseModel):
    source: str
    count: int


class VulnerabilityStats(BaseModel):
    by_severity: List[SeverityCount]
    by_source: List[SourceCount]


def _parse_cve_ids(raw: str | None) -> List[str]:
    if not raw:
        return []
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            return [str(x) for x in data]
    except json.JSONDecodeError:
        pass
    return []


@router.get("", response_model=List[VulnerabilityOut])
async def list_vulnerabilities(
    asset_id: Optional[int] = Query(None, ge=1),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    min_epss: Optional[float] = Query(None, ge=0.0, le=1.0),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    where = "WHERE v.no_vuln_found = 0"
    params: dict[str, Any] = {"lim": limit, "off": offset}
    if asset_id is not None:
        where += " AND v.asset_id = :asset_id"
        params["asset_id"] = asset_id
    if severity:
        where += " AND v.severity = :severity"
        params["severity"] = severity.lower()
    if min_epss is not None:
        where += " AND v.epss IS NOT NULL AND v.epss >= :min_epss"
        params["min_epss"] = min_epss

    sql = f"""
        SELECT
            v.vuln_id,
            v.asset_id,
            a.domain,
            v.ip,
            v.port,
            v.service,
            v.name,
            v.severity,
            v.cve_ids_json,
            v.cvss_score,
            v.cvss_severity,
            v.epss,
            v.source,
            v.module,
            v.matched_url,
            v.no_vuln_found
        FROM vulnerabilities v
        JOIN assets a ON a.asset_id = v.asset_id
        {where}
        ORDER BY v.epss DESC, v.cvss_score DESC, v.vuln_id DESC
        LIMIT :lim OFFSET :off
    """
    with engine.connect() as conn:
        rows = conn.execute(text(sql), params).fetchall()

    return [
        VulnerabilityOut(
            vuln_id=int(r[0]),
            asset_id=int(r[1]),
            domain=r[2],
            ip=r[3],
            port=int(r[4]),
            service=r[5],
            name=r[6],
            severity=r[7] or "unknown",
            cve_ids=_parse_cve_ids(r[8]),
            cvss_score=float(r[9]) if r[9] is not None else None,
            cvss_severity=r[10],
            epss=float(r[11]) if r[11] is not None else None,
            source=r[12] or "unknown",
            module=r[13],
            matched_url=r[14],
            no_vuln_found=bool(r[15]),
        )
        for r in rows
    ]


@router.get("/stats", response_model=VulnerabilityStats)
async def vulnerability_stats():
    with engine.connect() as conn:
        sev_rows = conn.execute(
            text("""
                SELECT severity, COUNT(*) AS c
                FROM vulnerabilities
                WHERE no_vuln_found = 0
                GROUP BY severity
                ORDER BY c DESC
            """)
        ).fetchall()
        src_rows = conn.execute(
            text("""
                SELECT source, COUNT(*) AS c
                FROM vulnerabilities
                WHERE no_vuln_found = 0
                GROUP BY source
                ORDER BY c DESC
                LIMIT 20
            """)
        ).fetchall()

    return VulnerabilityStats(
        by_severity=[SeverityCount(severity=r[0] or "unknown", count=int(r[1])) for r in sev_rows],
        by_source=[SourceCount(source=r[0] or "unknown", count=int(r[1])) for r in src_rows],
    )
