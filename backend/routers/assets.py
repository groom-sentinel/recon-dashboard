# routers/assets.py
import json
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query, Path
from pydantic import BaseModel
from sqlalchemy import text

from db import engine

router = APIRouter(prefix="/assets", tags=["assets"])

_SEV_SCORE = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 0}

def _risk_level(max_score: int) -> str:
    if max_score >= 4:
        return "danger"
    if max_score >= 3:
        return "warning"
    return "safe"


class AssetListItem(BaseModel):
    id:         int
    ip:         Optional[str]
    name:       Optional[str]
    risk_level: str


class CVEItem(BaseModel):
    id:       str
    desc:     str
    severity: str


class AssetDetail(BaseModel):
    id:              int
    ip:              Optional[str]
    name:            Optional[str]
    risk_level:      str
    cves:            List[CVEItem]
    recommendations: List[str]


@router.get("", response_model=List[AssetListItem])
async def list_assets(
    risk: str = Query(None, description="safe, warning, danger 중 선택"),
    sort: str = Query("id", description="id 또는 name 으로 정렬"),
):
    with engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT
                a.asset_id,
                a.domain,
                a.ip,
                COALESCE(MAX(
                    CASE v.severity
                        WHEN 'critical' THEN 5
                        WHEN 'high'     THEN 4
                        WHEN 'medium'   THEN 3
                        WHEN 'low'      THEN 2
                        WHEN 'info'     THEN 1
                        ELSE 0
                    END
                ), 0) AS max_sev_score
            FROM assets a
            LEFT JOIN vulnerabilities v
                ON v.asset_id = a.asset_id AND v.no_vuln_found = 0
            GROUP BY a.asset_id, a.domain, a.ip
        """)).fetchall()

    items = [
        {
            "id":         r[0],
            "name":       r[1],
            "ip":         r[2],
            "risk_level": _risk_level(r[3]),
        }
        for r in rows
    ]

    if risk:
        items = [a for a in items if a["risk_level"] == risk]

    if sort == "name":
        items.sort(key=lambda a: (a["name"] or ""))
    else:
        items.sort(key=lambda a: a["id"])

    return [AssetListItem(**a) for a in items]


@router.get("/{asset_id}", response_model=AssetDetail)
async def get_asset(asset_id: int = Path(..., ge=1)):
    with engine.connect() as conn:
        asset_row = conn.execute(
            text("SELECT asset_id, domain, ip FROM assets WHERE asset_id = :id"),
            {"id": asset_id},
        ).fetchone()
        if asset_row is None:
            raise HTTPException(status_code=404, detail="Asset not found")

        vuln_rows = conn.execute(
            text("""
                SELECT name, severity, cve_ids_json
                FROM vulnerabilities
                WHERE asset_id = :id AND no_vuln_found = 0
            """),
            {"id": asset_id},
        ).fetchall()

        scan_rows = conn.execute(
            text("SELECT port, service FROM service_scans WHERE asset_id = :id"),
            {"id": asset_id},
        ).fetchall()

    max_score = max((_SEV_SCORE.get(v[1], 0) for v in vuln_rows), default=0)

    cves: List[CVEItem] = []
    for name, severity, cve_ids_json in vuln_rows:
        cve_ids = json.loads(cve_ids_json) if cve_ids_json else []
        cve_id = cve_ids[0] if cve_ids else name
        cves.append(CVEItem(id=cve_id, desc=name, severity=severity))

    recommendations = _build_recommendations(scan_rows, vuln_rows)

    return AssetDetail(
        id=asset_row[0],
        name=asset_row[1],
        ip=asset_row[2],
        risk_level=_risk_level(max_score),
        cves=cves,
        recommendations=recommendations,
    )


_PORT_RECS = {
    22:   "SSH 포트(22) 접근을 특정 IP로 제한하세요.",
    23:   "Telnet(23)은 암호화되지 않습니다. SSH로 전환하세요.",
    80:   "HTTP(80)를 HTTPS(443)로 리다이렉트하세요.",
    443:  "TLS 인증서 유효기간과 설정을 점검하세요.",
    3306: "MySQL(3306)을 외부에 직접 노출하지 마세요.",
    5432: "PostgreSQL(5432)을 외부에 직접 노출하지 마세요.",
    6379: "Redis(6379) 인증 설정 및 외부 노출 여부를 확인하세요.",
    21:   "FTP(21)는 암호화되지 않습니다. SFTP/FTPS로 전환하세요.",
    25:   "SMTP(25) 오픈 릴레이 여부를 점검하세요.",
    8080: "개발용 포트(8080)가 외부에 노출되어 있습니다.",
}

def _build_recommendations(scan_rows, vuln_rows) -> List[str]:
    recs: List[str] = []
    seen: set = set()

    for port, _ in scan_rows:
        rec = _PORT_RECS.get(port)
        if rec and rec not in seen:
            recs.append(rec)
            seen.add(rec)

    has_critical = any(_SEV_SCORE.get(v[1], 0) >= 5 for v in vuln_rows)
    has_high     = any(_SEV_SCORE.get(v[1], 0) >= 4 for v in vuln_rows)
    if has_critical:
        recs.insert(0, "즉시 패치가 필요한 Critical 취약점이 존재합니다.")
    elif has_high:
        recs.insert(0, "High 등급 취약점에 대한 패치를 적용하세요.")

    return recs
