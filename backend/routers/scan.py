# routers/scan.py
import socket
import subprocess
import xml.etree.ElementTree as ET
from typing import Dict, Any, List

from fastapi import APIRouter, HTTPException
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel

router = APIRouter(tags=["scan"])   # (원한다면 prefix="/scan" 으로 설정해도 됩니다)

# 요청 모델
class ScanRequest(BaseModel):
    target: str

# 스캔 함수
def real_portscan_subprocess(target: str, ip: str) -> Dict[str, Any]:
    cmd = [
        "nmap",
        "-Pn", "-n", "-T4",
        "-sT",          # root 권한 없이 동작
        "-p1-1024", "-sV",
        "-oX", "-",     # XML 출력
        target
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"nmap 실패: {proc.stderr or proc.stdout}")

    root = ET.fromstring(proc.stdout)
    host_el = root.find("host")
    ports_el = host_el.find("ports")

    open_ports: List[Dict[str, Any]] = []
    for port_el in ports_el.findall("port"):
        if port_el.find("state").get("state") != "open":
            continue
        svc = port_el.find("service")
        open_ports.append({
            "port":    int(port_el.get("portid")),
            "service": svc.get("name", ""),
            "version": svc.get("version", ""),
        })

    # 샘플 매핑: 자산·취약점·위험도
    assets         = [{"id":1, "ip":ip, "name":target}]
    vulnerabilities = []
    risks           = []
    for idx, p in enumerate(open_ports, start=1):
        if p["port"] == 22:
            sev, lvl, name = "high",   "danger",  "SSH(22) open"
        elif p["port"] == 80:
            sev, lvl, name = "medium", "warning", "HTTP(80) open"
        else:
            sev, lvl, name = "low",    "safe",    f"Port {p['port']} open"

        vulnerabilities.append({
            "id": idx, "asset_id": 1,
            "name": name, "severity": sev
        })
        risks.append({
            "asset_id": 1, "level": lvl
        })

    return {
        "target":          target,
        "ip":              ip,
        "ports":           open_ports,
        "assets":          assets,
        "vulnerabilities": vulnerabilities,
        "risks":           risks,
    }

# POST /scan 엔드포인트
@router.post("/scan")
async def scan(req: ScanRequest):
    tgt = req.target.strip()
    if not tgt:
        raise HTTPException(400, "target이 비어 있습니다.")
    try:
        ip = socket.gethostbyname(tgt)
    except socket.gaierror:
        raise HTTPException(400, "도메인을 찾을 수 없습니다.")
    # 블로킹 함수를 쓰레드 풀에 위임
    return await run_in_threadpool(real_portscan_subprocess, tgt, ip)