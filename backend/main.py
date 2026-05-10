# main.py (FastAPI)
# main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# routers 패키지에서 가져오기
from routers import scan, dashboard, assets

app = FastAPI()

# CORS 설정
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 필요에 따라 호스트 제한
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 각 기능별 라우터 등록
app.include_router(scan)          # /scan
app.include_router(dashboard)     # /dashboard/summary
app.include_router(assets)        # /assets, /assets/{id}

# (기존 scan 엔드포인트와 real_portscan_subprocess 코드는 모두 삭제합니다)