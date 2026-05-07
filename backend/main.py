# backend/main.py
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI()

# CORS 설정 - 로컬 React(3000)에서 호출 허용
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # or ["http://localhost:3000"]
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 요청 바디용 모델 정의 (POST /scan)
class ScanRequest(BaseModel):
    target: str

# 모의(Mock) 스캔 데이터 - 나중에 실제 코드로 교체
def fake_portscan(target: str):
    return {
      "assets": [{"id":1,"ip":target,"name":target}],
      "vulnerabilities": [
        {"id":1,"asset_id":1,"name":"Port 22 open","severity":"high"},
        {"id":2,"asset_id":1,"name":"Port 80 open","severity":"medium"},
      ],
      "risks": [{"asset_id":1,"level":"danger"}]
    }

@app.get("/health")
async def health():
    return {"status": "ok"}

# POST /scan 엔드포인트
@app.post("/scan")
async def scan(req: ScanRequest):
    target = req.target.strip()
    if not target:
        raise HTTPException(status_code=400, detail="target이 비어 있습니다.")
    # 여기서 실제 포트스캐너 코드를 호출하거나
    # fake_portscan을 대체하면 됩니다.
    result = fake_portscan(target)
    return result