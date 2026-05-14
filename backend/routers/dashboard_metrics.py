"""PDF '대시보드_구현' 기준 집계 API (DB 필드 → 시각화용 JSON)."""

from __future__ import annotations

import json
import re
from collections import Counter
from typing import Any, List, Optional

from fastapi import APIRouter, Query
from pydantic import BaseModel
from sqlalchemy import text

from db import engine

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


# --- PDF 2: Asset Discovery ---


class DailyCount(BaseModel):
    date: str
    count: int


class NamedCount(BaseModel):
    name: str
    count: int


# --- PDF 4: Service ---


class OsCount(BaseModel):
    os: str
    count: int


class ProductCount(BaseModel):
    product: str
    count: int


class HttpServerCount(BaseModel):
    server: str
    count: int


# --- PDF 6: Exploit ---


class ExploitBucket(BaseModel):
    status: str
    count: int


class CveHit(BaseModel):
    cve_id: str
    count: int


class NoVulnMetric(BaseModel):
    no_vuln_rate_percent: float
    no_vuln_rows: int
    total_rows: int


# --- PDF 7: Remediation ---


class RemediationRow(BaseModel):
    vuln_id: int
    asset_id: int
    domain: Optional[str]
    ip: str
    port: int
    name: str
    severity: str
    cvss_score: Optional[float] = None
    exploit_result_preview: Optional[str] = None


class AssetRiskRow(BaseModel):
    asset_id: int
    domain: Optional[str]
    risk_score: float
    max_cvss: Optional[float] = None
    max_epss: Optional[float] = None


class HeatmapCell(BaseModel):
    domain: str
    severity: str
    count: int


def _parse_json_obj(raw: str | None) -> dict[str, Any]:
    if not raw or not str(raw).strip():
        return {}
    try:
        v = json.loads(raw)
        return v if isinstance(v, dict) else {}
    except json.JSONDecodeError:
        return {}


def _parse_json_list(raw: str | None) -> list[Any]:
    if not raw or not str(raw).strip():
        return []
    try:
        v = json.loads(raw)
        return v if isinstance(v, list) else []
    except json.JSONDecodeError:
        return []


def _classify_exploit(raw: str | None) -> str:
    """success / failure / not_attempted / unknown — 문자열 휴리스틱."""
    if raw is None:
        return "not_attempted"
    s = str(raw).strip()
    if s in ("", "{}", "null", "[]"):
        return "not_attempted"
    try:
        obj = json.loads(s)
    except json.JSONDecodeError:
        low = s.lower()
        if "success" in low and "fail" not in low[: low.find("success") + 1]:
            return "success"
        if "fail" in low or "error" in low:
            return "failure"
        return "unknown"

    blob = json.dumps(obj, ensure_ascii=False).lower()
    if isinstance(obj, dict):
        st = obj.get("status") or obj.get("result")
        if isinstance(st, str) and "success" in st.lower():
            return "success"
        if isinstance(st, str) and ("fail" in st.lower() or "error" in st.lower()):
            return "failure"
    if "job_id" in blob or "uuid" in blob:
        if re.search(r"\bsuccess\b", blob):
            return "success"
        if re.search(r"\b(fail|error|exception)\b", blob):
            return "failure"
        return "unknown"
    if "success" in blob:
        return "success"
    if "fail" in blob or "error" in blob:
        return "failure"
    return "unknown"


def _is_exploit_success(raw: str | None) -> bool:
    return _classify_exploit(raw) == "success"


@router.get("/asset-trend", response_model=List[DailyCount])
async def asset_trend(days: int = Query(30, ge=1, le=365)):
    with engine.connect() as conn:
        rows = conn.execute(
            text("""
                SELECT DATE(created_at) AS d, COUNT(*) AS c
                FROM assets
                WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL :days DAY)
                GROUP BY DATE(created_at)
                ORDER BY d ASC
            """),
            {"days": days},
        ).fetchall()
    return [DailyCount(date=str(r[0]), count=int(r[1])) for r in rows]


@router.get("/source-distribution", response_model=List[NamedCount])
async def source_distribution():
    with engine.connect() as conn:
        rows = conn.execute(
            text("SELECT source_json FROM assets WHERE source_json IS NOT NULL")
        ).fetchall()
    cnt: Counter[str] = Counter()
    for (raw,) in rows:
        for item in _parse_json_list(raw):
            if isinstance(item, str) and item.strip():
                cnt[item.strip()] += 1
    return [NamedCount(name=k, count=v) for k, v in cnt.most_common(50)]


@router.get("/cloud-distribution", response_model=List[NamedCount])
async def cloud_distribution():
    with engine.connect() as conn:
        rows = conn.execute(
            text("SELECT discovery_json FROM assets WHERE discovery_json IS NOT NULL")
        ).fetchall()
    cnt: Counter[str] = Counter()
    for (raw,) in rows:
        d = _parse_json_obj(raw)
        asn = d.get("asn_info") or {}
        if not isinstance(asn, dict):
            continue
        cp = asn.get("cloud_provider") or asn.get("cloudProvider")
        if isinstance(cp, str) and cp.strip():
            cnt[cp.strip().lower()] += 1
        else:
            cnt["(미분류)"] += 1
    out = [NamedCount(name=k, count=v) for k, v in cnt.most_common(20)]
    return out


@router.get("/os-distribution", response_model=List[OsCount])
async def os_distribution():
    with engine.connect() as conn:
        rows = conn.execute(
            text("""
                SELECT COALESCE(NULLIF(TRIM(os), ''), 'Unknown') AS os_label, COUNT(*) AS c
                FROM service_scans
                GROUP BY os_label
                ORDER BY c DESC
                LIMIT 30
            """)
        ).fetchall()
    return [OsCount(os=r[0] or "Unknown", count=int(r[1])) for r in rows]


@router.get("/product-top", response_model=List[ProductCount])
async def product_top(limit: int = Query(10, ge=1, le=50)):
    with engine.connect() as conn:
        rows = conn.execute(
            text("""
                SELECT COALESCE(NULLIF(TRIM(product), ''), 'Unknown') AS p, COUNT(*) AS c
                FROM service_scans
                GROUP BY p
                ORDER BY c DESC
                LIMIT :lim
            """),
            {"lim": limit},
        ).fetchall()
    return [ProductCount(product=r[0], count=int(r[1])) for r in rows]


@router.get("/http-server-distribution", response_model=List[HttpServerCount])
async def http_server_distribution(limit: int = Query(20, ge=1, le=50)):
    with engine.connect() as conn:
        rows = conn.execute(
            text("""
                SELECT
                    COALESCE(
                        NULLIF(JSON_UNQUOTE(JSON_EXTRACT(http_info_json, '$.server')), ''),
                        'Unknown'
                    ) AS srv,
                    COUNT(*) AS c
                FROM service_scans
                GROUP BY srv
                ORDER BY c DESC
                LIMIT :lim
            """),
            {"lim": limit},
        ).fetchall()
    return [HttpServerCount(server=r[0] or "Unknown", count=int(r[1])) for r in rows]


@router.get("/exploit-buckets", response_model=List[ExploitBucket])
async def exploit_buckets():
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT exploit_result_json FROM vulnerabilities WHERE no_vuln_found = 0"
            )
        ).fetchall()
    c: Counter[str] = Counter()
    for (raw,) in rows:
        c[_classify_exploit(raw)] += 1
    order = ("success", "failure", "not_attempted", "unknown")
    out = [ExploitBucket(status=k, count=c[k]) for k in order if c[k]]
    for k, v in c.items():
        if k not in order:
            out.append(ExploitBucket(status=k, count=v))
    return out


@router.get("/exploit-success-top-cves", response_model=List[CveHit])
async def exploit_success_top_cves(limit: int = Query(10, ge=1, le=50)):
    with engine.connect() as conn:
        rows = conn.execute(
            text("""
                SELECT cve_ids_json, exploit_result_json
                FROM vulnerabilities
                WHERE no_vuln_found = 0
            """)
        ).fetchall()
    hits: Counter[str] = Counter()
    for cve_raw, ex_raw in rows:
        if not _is_exploit_success(ex_raw):
            continue
        ids = _parse_json_list(cve_raw) if cve_raw else []
        for cid in ids:
            if isinstance(cid, str) and cid.upper().startswith("CVE-"):
                hits[cid.upper()] += 1
    return [CveHit(cve_id=k, count=v) for k, v in hits.most_common(limit)]


@router.get("/no-vuln-metric", response_model=NoVulnMetric)
async def no_vuln_metric():
    with engine.connect() as conn:
        row = conn.execute(
            text("""
                SELECT
                    SUM(CASE WHEN no_vuln_found = 1 THEN 1 ELSE 0 END) AS nok,
                    COUNT(*) AS tot
                FROM vulnerabilities
            """)
        ).fetchone()
    nok = int(row[0] or 0)
    tot = int(row[1] or 0)
    rate = round((nok * 100.0 / tot), 2) if tot else 0.0
    return NoVulnMetric(
        no_vuln_rate_percent=rate, no_vuln_rows=nok, total_rows=tot
    )


@router.get("/remediation-queue", response_model=List[RemediationRow])
async def remediation_queue(limit: int = Query(50, ge=1, le=200)):
    fetch = max(limit * 4, limit)
    with engine.connect() as conn:
        rows = conn.execute(
            text("""
                SELECT
                    v.vuln_id,
                    v.asset_id,
                    a.domain,
                    v.ip,
                    v.port,
                    v.name,
                    v.severity,
                    v.cvss_score,
                    v.exploit_result_json
                FROM vulnerabilities v
                JOIN assets a ON a.asset_id = v.asset_id
                WHERE v.no_vuln_found = 0
                  AND v.severity IN ('critical', 'high')
                ORDER BY v.cvss_score DESC, v.epss DESC, v.vuln_id DESC
                LIMIT :lim
            """),
            {"lim": fetch},
        ).fetchall()

    def _preview(raw: Any) -> Optional[str]:
        if raw is None:
            return None
        s = str(raw)
        return (s[:200] + "…") if len(s) > 200 else s

    ranked: list[tuple[float, int, RemediationRow]] = []
    for r in rows:
        raw_ex = r[8]
        row = RemediationRow(
            vuln_id=int(r[0]),
            asset_id=int(r[1]),
            domain=r[2],
            ip=r[3],
            port=int(r[4]),
            name=r[5],
            severity=r[6] or "unknown",
            cvss_score=float(r[7]) if r[7] is not None else None,
            exploit_result_preview=_preview(raw_ex),
        )
        ok = 0 if _is_exploit_success(raw_ex) else 1
        cv = -(row.cvss_score or 0.0)
        ranked.append((ok, cv, row))
    ranked.sort(key=lambda t: (t[0], t[1]))
    return [t[2] for t in ranked[:limit]]


@router.get("/asset-risk-ranking", response_model=List[AssetRiskRow])
async def asset_risk_ranking(limit: int = Query(20, ge=1, le=100)):
    with engine.connect() as conn:
        rows = conn.execute(
            text("""
                SELECT
                    a.asset_id,
                    a.domain,
                    MAX(v.cvss_score) AS max_cvss,
                    MAX(v.epss) AS max_epss
                FROM assets a
                INNER JOIN vulnerabilities v ON v.asset_id = a.asset_id AND v.no_vuln_found = 0
                GROUP BY a.asset_id, a.domain
                ORDER BY (COALESCE(MAX(v.cvss_score), 0) + COALESCE(MAX(v.epss), 0) * 10.0) DESC
                LIMIT :lim
            """),
            {"lim": limit},
        ).fetchall()
    out: List[AssetRiskRow] = []
    for r in rows:
        max_cvss = float(r[2]) if r[2] is not None else None
        max_epss = float(r[3]) if r[3] is not None else None
        score = (max_cvss or 0.0) + (max_epss or 0.0) * 10.0
        out.append(
            AssetRiskRow(
                asset_id=int(r[0]),
                domain=r[1],
                risk_score=round(score, 3),
                max_cvss=max_cvss,
                max_epss=max_epss,
            )
        )
    return out


@router.get("/domain-severity-heatmap", response_model=List[HeatmapCell])
async def domain_severity_heatmap(limit_domains: int = Query(25, ge=5, le=80)):
    with engine.connect() as conn:
        rows = conn.execute(
            text("""
                SELECT a.domain, LOWER(v.severity) AS sev, COUNT(*) AS c
                FROM vulnerabilities v
                INNER JOIN assets a ON a.asset_id = v.asset_id
                WHERE v.no_vuln_found = 0 AND a.domain IS NOT NULL AND a.domain != ''
                GROUP BY a.domain, LOWER(v.severity)
            """)
        ).fetchall()
    dom_tot: Counter[str] = Counter()
    cells: List[HeatmapCell] = []
    for domain, sev, c in rows:
        if not domain:
            continue
        sev_n = (sev or "unknown").lower()
        dom_tot[str(domain)] += int(c)
        cells.append(
            HeatmapCell(domain=str(domain), severity=sev_n, count=int(c))
        )
    top_domains = {d for d, _ in dom_tot.most_common(limit_domains)}
    return [c for c in cells if c.domain in top_domains]

