import os

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.engine import Engine

load_dotenv()


def _build_engine() -> Engine:
    host = os.environ["DB_HOST"]
    port = os.environ.get("DB_PORT", "3306")
    name = os.environ["DB_NAME"]
    user = os.environ["DB_USER"]
    password = os.environ["DB_PASSWORD"]
    url = f"mysql+pymysql://{user}:{password}@{host}:{port}/{name}?charset=utf8mb4"
    return create_engine(url, pool_pre_ping=True)


engine = _build_engine()
