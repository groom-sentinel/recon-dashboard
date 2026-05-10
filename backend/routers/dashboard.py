# routers/dashboard.py
from fastapi import APIRouter
from pydantic import BaseModel
from typing import List

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

# Pydantic 모델
class AssetSummary(BaseModel):
    name: str
    ports_count: int

class SummaryResponse(BaseModel):
    total_assets: int
    risky_assets: int
    critical_cves: int
    assets: List[AssetSummary]
    vuln_low: int
    vuln_medium: int
    vuln_high: int

# 예시용 메모리 자산 데이터
# 실제 서비스라면 DB나 캐시에 저장된 값을 여기에 꺼내 쓰세요.
_FAKE_ASSETS = [
    {
        "name": "scanme.nmap.org",
        "ports_count": 2,
        "risk_level": "danger",
        "cves": [
            {"id": "CVE-2023-1234", "severity": "critical"},
            {"id": "CVE-2023-5678", "severity": "medium"},
        ]
    },
    {
        "name": "example.com",
        "ports_count": 5,
        "risk_level": "warning",
        "cves": [
            {"id": "CVE-2023-0001", "severity": "low"},
        ]
    },
    # … 추가 자산 …
]

@router.get("/summary", response_model=SummaryResponse)
async def get_summary():
    # 1) 요약 통계 계산
    total_assets  = len(_FAKE_ASSETS)
    risky_assets  = sum(1 for a in _FAKE_ASSETS if a["risk_level"] != "safe")
    critical_cves = sum(
        1
        for a in _FAKE_ASSETS
        for c in a["cves"]
        if c.get("severity") == "critical"
    )

    # 2) assets 리스트 포맷
    assets_list = [
        AssetSummary(name=a["name"], ports_count=a["ports_count"])
        for a in _FAKE_ASSETS
    ]

    # 3) 취약점 심각도 별 카운트
    vuln_low    = sum(
        1 for a in _FAKE_ASSETS for c in a["cves"] if c.get("severity") == "low"
    )
    vuln_medium = sum(
        1 for a in _FAKE_ASSETS for c in a["cves"] if c.get("severity") == "medium"
    )
    vuln_high   = sum(
        1 for a in _FAKE_ASSETS for c in a["cves"] if c.get("severity") == "high"
    )

    # 4) 반환
    return SummaryResponse(
        total_assets=total_assets,
        risky_assets=risky_assets,
        critical_cves=critical_cves,
        assets=assets_list,
        vuln_low=vuln_low,
        vuln_medium=vuln_medium,
        vuln_high=vuln_high,
    )