# routers/assets.py
from fastapi import APIRouter, HTTPException, Query, Path
from pydantic import BaseModel
from typing import List

router = APIRouter(prefix="/assets", tags=["assets"])

# 응답 모델 정의
class AssetListItem(BaseModel):
    id:         int
    ip:         str
    name:       str
    risk_level: str

# GET /assets?risk=...&sort=...
@router.get("", response_model=List[AssetListItem])
async def list_assets(
    risk: str  = Query(None, description="safe, warning, danger 중 선택"),
    sort: str  = Query("id", description="id 또는 name 으로 정렬")
):
    # 실제 데이터 소스에서 assets 불러오기
    data = _FAKE_ASSETS.copy()   # 예시용 메모리 데이터
    if risk:
        data = [a for a in data if a["risk_level"] == risk]
    # id 나 name 으로 정렬
    data.sort(key=lambda a: a.get(sort))
    return [AssetListItem(**a) for a in data]

# 상세 조회용 모델
class CVEItem(BaseModel):
    id:       str
    desc:     str
    severity: str

class AssetDetail(BaseModel):
    id:              int
    ip:              str
    name:            str
    risk_level:      str
    cves:            List[CVEItem]
    recommendations: List[str]

# GET /assets/{asset_id}
@router.get("/{asset_id}", response_model=AssetDetail)
async def get_asset(
    asset_id: int = Path(..., ge=1, description="조회할 자산 ID")
):
    asset = next((a for a in _FAKE_ASSETS if a["id"] == asset_id), None)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    # cve 리스트를 모델에 맞춰 포맷팅
    cves = [CVEItem(**c) for c in asset["cves"]["all"]]
    return AssetDetail(
        id=asset["id"],
        ip=asset["ip"],
        name=asset["name"],
        risk_level=asset["risk_level"],
        cves=cves,
        recommendations=asset["recommendations"]
    )


# 예시용 메모리 데이터 (_FAKE_ASSETS는 main.py가 아닌 동일 모듈에 정의하거나 import)
_FAKE_ASSETS = [
    {
        "id": 1,
        "ip": "45.33.32.156",
        "name": "scanme.nmap.org",
        "risk_level": "danger",
        "cves": {
            "all": [
                {"id":"CVE-2023-1234","desc":"Test critical","severity":"critical"},
                {"id":"CVE-2023-4321","desc":"Test medium","severity":"medium"},
            ]
        },
        "recommendations": ["SSH 포트 차단", "패치 적용"],
    },
    # 필요시 더 추가…
]