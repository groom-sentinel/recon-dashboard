// src/api/dashboard.js
export async function loadDashboardData() {
  // 1) 요약 지표 가져오기
  const summaryRes = await fetch('http://127.0.0.1:8000/dashboard/summary')
  if (!summaryRes.ok) {
    const err = await summaryRes.json()
    throw new Error(err.detail || '요약 정보 로드 실패')
  }
  const summary = await summaryRes.json()

  // 2) 자산 목록 가져오기 (전체)
  const assetsRes = await fetch('http://127.0.0.1:8000/assets')
  if (!assetsRes.ok) {
    const err = await assetsRes.json()
    throw new Error(err.detail || '자산 목록 로드 실패')
  }
  const assets = await assetsRes.json()

  // 요약 API에서 가져온 critical CVE 건수는 summary.critical_cves
  // 자산 목록에서 위험도 분포(risk_level)와 취약점 심각도 분포를 직접 구해 보겠습니다.
  // (summary 에서 내려준다 해도 되고, 여기서 계산해도 무방)

  // 3) 위험도 분포 계산
  const riskCounts = { safe: 0, warning: 0, danger: 0 }
  assets.forEach(a => {
    if (riskCounts[a.risk_level] !== undefined) {
      riskCounts[a.risk_level]++
    }
  })

  // 4) 취약점 심각도 분포(가정: summary.vuln_low, summary.vuln_medium, summary.vuln_high 로 내려준다)
  //    만약 summary 에서 없으면 assets 각각을 /assets/{id} 로 조회해서 파싱해야 하는데,
  //    여기선 summary 에도 내려주는 걸로 가정합니다.
  const vulnCounts = {
    low:    summary.vuln_low    || 0,
    medium: summary.vuln_medium || 0,
    high:   summary.vuln_high   || 0,
  }

  return {
    summary,
    riskCounts,
    vulnCounts,
  }
}