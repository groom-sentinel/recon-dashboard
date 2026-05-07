backend : 
cd
python3 --version   # Python 3.x  확인
python3 -m venv venv
source venv/bin/activate # 가상환경
pip install fastapi uvicorn[standard] python-multipart # 없으면 설치
uvicorn main:app --reload --host 0.0.0.0 --port 8000 # 서버 실행

frontend : 
cd
npm start