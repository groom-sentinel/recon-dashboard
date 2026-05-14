import { apiUrl } from './base'

async function parseJsonError(res) {
  try {
    const body = await res.json()
    return body.detail || body.message || res.statusText
  } catch {
    return res.statusText
  }
}

async function jget(path, label) {
  const res = await fetch(apiUrl(path))
  if (!res.ok) {
    throw new Error(
      (await parseJsonError(res)) || `${label} 로드 실패 (${path})`
    )
  }
  return res.json()
}

/**
 * PDF '대시보드_구현' 전 구역용 데이터 병렬 로드.
 */
export async function loadDashboardData() {
  const [
    summary,
    assets,
    portExposure,
    serviceScans,
    highRiskScans,
    vulnStats,
    assetTrend,
    sourceDist,
    cloudDist,
    osDist,
    productTop,
    httpServers,
    exploitBuckets,
    exploitTopCves,
    noVulnMetric,
    remediation,
    riskRanking,
    heatmapCells,
    epssHigh,
  ] = await Promise.all([
    jget('/dashboard/summary', '요약'),
    jget('/assets', '자산'),
    jget('/dashboard/port-exposure?limit=20', '포트 노출'),
    jget('/service-scans?limit=100', '서비스 스캔'),
    jget('/service-scans?limit=80&high_risk_only=true', '고위험 포트'),
    jget('/vulnerabilities/stats', '취약점 통계'),
    jget('/dashboard/asset-trend?days=60', '자산 추이'),
    jget('/dashboard/source-distribution', '출처 분포'),
    jget('/dashboard/cloud-distribution', '클라우드 분포'),
    jget('/dashboard/os-distribution', 'OS 분포'),
    jget('/dashboard/product-top?limit=10', '제품 Top'),
    jget('/dashboard/http-server-distribution?limit=15', 'HTTP Server'),
    jget('/dashboard/exploit-buckets', '익스플로잇 버킷'),
    jget('/dashboard/exploit-success-top-cves?limit=10', 'CVE Top'),
    jget('/dashboard/no-vuln-metric', '무취약점 비율'),
    jget('/dashboard/remediation-queue?limit=40', '대응 큐'),
    jget('/dashboard/asset-risk-ranking?limit=15', '위험 랭킹'),
    jget('/dashboard/domain-severity-heatmap?limit_domains=20', '히트맵'),
    jget('/vulnerabilities?min_epss=0.7&limit=40', 'EPSS 고위험'),
  ])

  const riskCounts = { safe: 0, warning: 0, danger: 0 }
  assets.forEach((a) => {
    if (riskCounts[a.risk_level] !== undefined) {
      riskCounts[a.risk_level]++
    }
  })

  const vulnCounts = {
    critical: summary.vuln_critical ?? 0,
    high: summary.vuln_high ?? 0,
    medium: summary.vuln_medium ?? 0,
    low: summary.vuln_low ?? 0,
  }

  return {
    summary,
    assets,
    riskCounts,
    vulnCounts,
    portExposure,
    serviceScans,
    highRiskScans,
    vulnStats,
    assetTrend,
    sourceDist,
    cloudDist,
    osDist,
    productTop,
    httpServers,
    exploitBuckets,
    exploitTopCves,
    noVulnMetric,
    remediation,
    riskRanking,
    heatmapCells,
    epssHigh,
  }
}
