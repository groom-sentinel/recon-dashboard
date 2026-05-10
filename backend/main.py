# main.py (FastAPI)
import socket
import subprocess
import xml.etree.ElementTree as ET
import nmap
from typing import Dict, Any, List
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    target: str

def real_portscan_subprocess(target: str, ip: str) -> Dict[str, Any]:
    # 1) nmap 커맨드를 XML 출력으로 실행
    cmd = [
        "nmap",
        "-Pn",           # 호스트 다운 체크 건너뛰기
        "-n",            # DNS 리버스룩업 건너뛰기
        "-T4",           # 빠른 타이밍 템플릿
        "-sT",           # TCP connect 스캔 (root 불필요)
        "-p1-1024",      # 포트 범위
        "-sV",           # 서비스/버전 탐지
        "-oX", "-",      # XML 형태를 stdout 으로
        target
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"nmap 실패: {proc.stderr}")

    # 2) XML 파싱
    root = ET.fromstring(proc.stdout)
    host_el = root.find("host")
    ports_el = host_el.find("ports")

    open_ports: List[Dict[str, Any]] = []
    for port_el in ports_el.findall("port"):
        state = port_el.find("state").get("state")
        if state != "open":
            continue

        service_el = port_el.find("service")
        portid   = int(port_el.get("portid"))
        svc_name = service_el.get("name", "")
        svc_ver  = service_el.get("version", "")

        open_ports.append({
            "port": portid,
            "service": svc_name,
            "version": svc_ver
        })

    # 3) 간단한 자산/취약점/위험도 매핑 (샘플)
    assets = [{"id":1, "ip":ip, "name":target}]
    vulnerabilities = []
    risks = []
    for idx, p in enumerate(open_ports, start=1):
        if p["port"] == 22:
            sev, lvl = "high",   "danger"
            name     = "SSH(22) open"
        elif p["port"] == 80:
            sev, lvl = "medium", "warning"
            name     = "HTTP(80) open"
        else:
            sev, lvl = "low",    "safe"
            name     = f"Port {p['port']} open"

        vulnerabilities.append({
            "id": idx,
            "asset_id": 1,
            "name": name,
            "severity": sev
        })
        risks.append({
            "asset_id": 1,
            "level": lvl
        })

    return {
        "target": target,
        "ip": ip,
        "ports": open_ports,
        "assets": assets,
        "vulnerabilities": vulnerabilities,
        "risks": risks,
    }

@app.post("/scan")
async def scan(req: ScanRequest):
    target = req.target.strip()
    if not target:
        raise HTTPException(status_code=400, detail="target이 비어 있습니다.")
    # 1) 도메인(DNS) 해석 시도
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        # 해석 실패 시 400 에러 리턴
        raise HTTPException(status_code=400, detail="도메인을 찾을 수 없습니다.")
    # 블로킹인 subprocess 호출을 쓰레드 풀로 offload
    result = await run_in_threadpool(real_portscan_subprocess, target, ip)
    return result