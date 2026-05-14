"""Open ports / service fingerprint rows for the dashboard."""

from __future__ import annotations

import json
from typing import Any, List, Optional

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field
from sqlalchemy import text

from db import engine

router = APIRouter(prefix="/service-scans", tags=["service_scans"])

# PDF 고위험 포트 필터 (22, 23, 3389, 445, 1433)
_HIGH_RISK_PORTS = (22, 23, 3389, 445, 1433)


class ServiceScanOut(BaseModel):
    scan_id: int
    asset_id: int
    domain: Optional[str] = None
    ip: str
    port: int
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    os: Optional[str] = None
    http_info: dict[str, Any] = Field(default_factory=dict)
    scanned_at: Optional[str] = None


def _parse_http_info(raw: str | None) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}
    except json.JSONDecodeError:
        return {}


@router.get("", response_model=List[ServiceScanOut])
async def list_service_scans(
    asset_id: Optional[int] = Query(None, ge=1),
    high_risk_only: bool = Query(False, description="Restrict to common sensitive ports"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    in_ports = ",".join(str(p) for p in _HIGH_RISK_PORTS)
    where_extra = ""
    params: dict[str, Any] = {"lim": limit, "off": offset}
    if asset_id is not None:
        where_extra += " AND s.asset_id = :asset_id"
        params["asset_id"] = asset_id
    if high_risk_only:
        where_extra += f" AND s.port IN ({in_ports})"

    sql = f"""
        SELECT
            s.scan_id,
            s.asset_id,
            a.domain,
            s.ip,
            s.port,
            s.service,
            s.product,
            s.version,
            s.os,
            s.http_info_json,
            s.scanned_at
        FROM service_scans s
        JOIN assets a ON a.asset_id = s.asset_id
        WHERE 1=1
        {where_extra}
        ORDER BY s.scanned_at DESC, s.scan_id DESC
        LIMIT :lim OFFSET :off
    """
    with engine.connect() as conn:
        rows = conn.execute(text(sql), params).fetchall()

    out: List[ServiceScanOut] = []
    for r in rows:
        scanned = r[10]
        out.append(
            ServiceScanOut(
                scan_id=int(r[0]),
                asset_id=int(r[1]),
                domain=r[2],
                ip=r[3],
                port=int(r[4]),
                service=r[5],
                product=r[6],
                version=r[7],
                os=r[8],
                http_info=_parse_http_info(r[9]),
                scanned_at=scanned.strftime("%Y-%m-%d %H:%M:%S") if scanned is not None else None,
            )
        )
    return out
