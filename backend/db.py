import os
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.engine import Engine

# backend/.env 를 모듈 위치 기준으로 로드 (실행 cwd와 무관)
load_dotenv(Path(__file__).resolve().parent / ".env")


def _build_engine() -> Engine:
    host = os.environ.get("DB_HOST")
    if not host:
        raise RuntimeError(
            "DB_HOST가 없습니다. backend 폴더에 .env 를 두고 "
            "backend/.env.example 의 변수를 채워 주세요."
        )
    port = os.environ.get("DB_PORT", "3306")
    name = os.environ.get("DB_NAME")
    user = os.environ.get("DB_USER")
    password = os.environ.get("DB_PASSWORD", "")
    if not name or not user:
        raise RuntimeError(
            "DB_NAME 또는 DB_USER가 없습니다. backend/.env 를 확인하세요."
        )
    url = f"mysql+pymysql://{user}:{password}@{host}:{port}/{name}?charset=utf8mb4"
    return create_engine(url, pool_pre_ping=True)


engine = _build_engine()
