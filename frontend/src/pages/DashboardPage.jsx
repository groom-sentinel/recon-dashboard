// src/pages/DashboardPage.jsx — PDF '대시보드_구현' 섹션 순
import React, { useEffect, useMemo, useState } from 'react'
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  LineChart,
  Line,
} from 'recharts'
import { loadDashboardData } from '../api/dashboard'

const PDF_HIGH_RISK = new Set([22, 23, 3389, 445, 1433])

const RISK_COLORS = {
  safe: '#60a5fa',
  warning: '#facc15',
  danger: '#ef4444',
}

const VULN_COLORS = {
  critical: '#7f1d1d',
  high: '#ef4444',
  medium: '#f59e0b',
  low: '#10b981',
  info: '#94a3b8',
  unknown: '#cbd5e1',
}

const SEVERITY_ORDER = [
  'critical',
  'high',
  'medium',
  'low',
  'info',
  'unknown',
]

function SectionTitle({ children }) {
  return (
    <h2
      style={{
        margin: '28px 0 12px',
        fontSize: 18,
        fontWeight: 700,
        color: '#0f172a',
        borderBottom: '2px solid #e2e8f0',
        paddingBottom: 6,
      }}
    >
      {children}
    </h2>
  )
}

function Donut({ data, colors, nameKey = 'name', valueKey = 'value' }) {
  if (!data || data.length === 0) {
    return <p style={{ color: '#94a3af' }}>데이터 없음</p>
  }
  return (
    <ResponsiveContainer width="100%" height={260}>
      <PieChart>
        <Pie
          data={data}
          dataKey={valueKey}
          nameKey={nameKey}
          innerRadius={52}
          outerRadius={88}
          paddingAngle={1}
          label={(e) => `${e[nameKey]}: ${e[valueKey]}`}
        >
          {data.map((e, i) => (
            <Cell
              key={i}
              fill={
                colors[e[nameKey]] ||
                colors[e.severity] ||
                ['#6366f1', '#8b5cf6', '#ec4899', '#14b8a6', '#f97316'][i % 5]
              }
            />
          ))}
        </Pie>
        <Tooltip />
      </PieChart>
    </ResponsiveContainer>
  )
}

function buildHeatmapRows(cells) {
  const domains = [...new Set((cells || []).map((c) => c.domain))].sort()
  const map = new Map()
  let maxC = 0
  ;(cells || []).forEach((c) => {
    const k = `${c.domain}|${c.severity}`
    map.set(k, c.count)
    if (c.count > maxC) maxC = c.count
  })
  const rows = domains.map((d) => {
    const o = { domain: d }
    SEVERITY_ORDER.forEach((s) => {
      o[s] = map.get(`${d}|${s}`) || 0
    })
    return o
  })
  return { rows, maxC: maxC || 1 }
}

function heatColor(n, max) {
  if (!n) return '#f8fafc'
  const t = Math.min(1, n / max)
  const r = Math.round(254 - t * 180)
  const g = Math.round(242 - t * 100)
  const b = Math.round(242 - t * 120)
  return `rgb(${r},${g},${b})`
}

const th = {
  borderBottom: '1px solid #e5e7eb',
  padding: '8px 6px',
  fontWeight: 600,
  fontSize: 12,
  textAlign: 'left',
}
const td = {
  borderBottom: '1px solid #f1f5f9',
  padding: '6px',
  fontSize: 12,
  verticalAlign: 'top',
}

export default function DashboardPage() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    ;(async () => {
      setLoading(true)
      try {
        setData(await loadDashboardData())
      } catch (e) {
        setError(e.message)
      } finally {
        setLoading(false)
      }
    })()
  }, [])

  const heatmap = useMemo(
    () => buildHeatmapRows(data?.heatmapCells),
    [data]
  )

  if (loading) {
    return (
      <p style={{ textAlign: 'center', padding: '40px' }}>불러오는 중…</p>
    )
  }
  if (error) {
    return (
      <p style={{ textAlign: 'center', color: 'red', padding: '24px' }}>
        {error}
      </p>
    )
  }

  const {
    summary,
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
    epssHigh,
  } = data

  const riskPieData = Object.entries(riskCounts)
    .map(([k, v]) => ({ name: k, value: v }))
    .filter((x) => x.value > 0)

  const vulnPieData = Object.entries(vulnCounts)
    .map(([k, v]) => ({ name: k, value: v }))
    .filter((x) => x.value > 0)

  const severityDonutData = (vulnStats?.by_severity || []).map((x) => ({
    name: x.severity,
    value: x.count,
  }))

  const exploitDonutData = (exploitBuckets || []).map((x) => ({
    name: x.status,
    value: x.count,
  }))

  const portExposureH = (portExposure || []).map((p) => ({
    label: `${p.port}`,
    assets: p.assets,
  }))

  return (
    <main
      style={{
        maxWidth: 1180,
        margin: '0 auto',
        padding: '20px 16px 56px',
        fontFamily: 'system-ui, sans-serif',
        color: '#0f172a',
      }}
    >
      <h1 style={{ fontSize: 28, fontWeight: 800, marginBottom: 4 }}>
        대시보드 (팀 스펙)
      </h1>
      <p style={{ margin: '0 0 8px', color: '#64748b', fontSize: 14 }}>
        DB 필드 집계 → PDF 시각화 형태
      </p>

      {/* 1. KPI */}
      <SectionTitle>1. 전체 현황 요약 (KPI)</SectionTitle>
      <div
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          gap: 14,
          marginBottom: 8,
        }}
      >
        {[
          { label: '전체 자산 수 (assets)', value: summary.total_assets },
          {
            label: '위험 자산 수 (critical+high, distinct)',
            value: summary.risky_assets,
          },
          {
            label: 'Critical 취약점 건수',
            value: summary.critical_cves,
          },
        ].map((c) => (
          <div
            key={c.label}
            style={{
              flex: '1 1 220px',
              background: '#fff',
              border: '1px solid #e2e8f0',
              borderRadius: 10,
              padding: 16,
              boxShadow: '0 1px 2px rgba(0,0,0,0.04)',
            }}
          >
            <div style={{ fontSize: 12, color: '#64748b' }}>{c.label}</div>
            <div style={{ fontSize: 30, fontWeight: 800, marginTop: 6 }}>
              {c.value}
            </div>
          </div>
        ))}
      </div>

      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 24, marginBottom: 8 }}>
        <div style={{ flex: '1 1 300px' }}>
          <h3 style={{ fontSize: 14, fontWeight: 600, marginBottom: 8 }}>
            자산 위험도 (앱 로직)
          </h3>
          {riskPieData.length ? (
            <Donut data={riskPieData} colors={RISK_COLORS} />
          ) : (
            <p style={{ color: '#94a3b8' }}>없음</p>
          )}
        </div>
        <div style={{ flex: '1 1 300px' }}>
          <h3 style={{ fontSize: 14, fontWeight: 600, marginBottom: 8 }}>
            취약점 심각도 (건수, summary)
          </h3>
          {vulnPieData.length ? (
            <Donut data={vulnPieData} colors={VULN_COLORS} />
          ) : (
            <p style={{ color: '#94a3b8' }}>없음</p>
          )}
        </div>
      </div>

      {/* 2. Asset Discovery */}
      <SectionTitle>2. Asset Discovery</SectionTitle>
      <h3 style={{ fontSize: 14, fontWeight: 600, margin: '0 0 8px' }}>
        신규 자산 추이 (assets.created_at 일별)
      </h3>
      <div style={{ width: '100%', height: 280, marginBottom: 20 }}>
        {!assetTrend?.length ? (
          <p style={{ color: '#94a3b8' }}>추이 데이터 없음</p>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={assetTrend} margin={{ left: 8, right: 8, top: 8 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
              <XAxis dataKey="date" tick={{ fontSize: 11 }} />
              <YAxis allowDecimals={false} />
              <Tooltip />
              <Line
                type="monotone"
                dataKey="count"
                stroke="#2563eb"
                strokeWidth={2}
                dot={{ r: 3 }}
                name="신규 자산"
              />
            </LineChart>
          </ResponsiveContainer>
        )}
      </div>

      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 24 }}>
        <div style={{ flex: '1 1 300px' }}>
          <h3 style={{ fontSize: 14, fontWeight: 600, marginBottom: 8 }}>
            인프라 유형 (discovery_json → cloud_provider)
          </h3>
          <Donut
            data={(cloudDist || []).map((x) => ({ name: x.name, value: x.count }))}
            colors={{}}
          />
        </div>
        <div style={{ flex: '1 1 300px' }}>
          <h3 style={{ fontSize: 14, fontWeight: 600, marginBottom: 8 }}>
            자산 출처 (source_json 배열)
          </h3>
          <Donut
            data={(sourceDist || []).map((x) => ({ name: x.name, value: x.count }))}
            colors={{}}
          />
        </div>
      </div>

      {/* 3. Port Scanner */}
      <SectionTitle>3. Port Scanner</SectionTitle>
      <h3 style={{ fontSize: 14, fontWeight: 600, margin: '0 0 8px' }}>
        포트별 노출 자산 수 (수평 바)
      </h3>
      <div style={{ width: '100%', height: 300, marginBottom: 20 }}>
        {!portExposureH.length ? (
          <p style={{ color: '#94a3b8' }}>service_scans 없음</p>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <BarChart
              layout="vertical"
              data={portExposureH}
              margin={{ left: 16, right: 16, top: 8, bottom: 8 }}
            >
              <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
              <XAxis type="number" allowDecimals={false} />
              <YAxis
                type="category"
                dataKey="label"
                width={44}
                tick={{ fontSize: 11 }}
              />
              <Tooltip />
              <Bar dataKey="assets" fill="#3b82f6" radius={[0, 4, 4, 0]} name="자산 수" />
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>

      <h3 style={{ fontSize: 14, fontWeight: 600, margin: '0 0 8px' }}>
        고위험 포트 (22,23,3389,445,1433) — 하이라이트 테이블
      </h3>
      <div style={{ overflowX: 'auto', marginBottom: 16 }}>
        <table
          style={{
            width: '100%',
            borderCollapse: 'collapse',
            fontSize: 12,
            background: '#fff',
            border: '1px solid #e2e8f0',
          }}
        >
          <thead>
            <tr style={{ background: '#fef3c7' }}>
              <th style={th}>도메인</th>
              <th style={th}>IP</th>
              <th style={th}>Port</th>
              <th style={th}>Service</th>
              <th style={th}>Product</th>
              <th style={th}>Version</th>
            </tr>
          </thead>
          <tbody>
            {!(highRiskScans || []).length ? (
              <tr>
                <td colSpan={6} style={{ ...td, color: '#94a3b8' }}>
                  해당 포트 스캔 없음
                </td>
              </tr>
            ) : (
              highRiskScans.map((row) => (
                <tr key={row.scan_id}>
                  <td style={td}>{row.domain || '—'}</td>
                  <td style={td}>{row.ip}</td>
                  <td style={td}>
                    <strong>{row.port}</strong>
                  </td>
                  <td style={td}>{row.service || '—'}</td>
                  <td style={td}>{row.product || '—'}</td>
                  <td style={td}>{row.version || '—'}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <h3 style={{ fontSize: 14, fontWeight: 600, margin: '0 0 8px' }}>
        포트/서비스/버전 원시 (최근)
      </h3>
      <div style={{ overflowX: 'auto', marginBottom: 8 }}>
        <table
          style={{
            width: '100%',
            borderCollapse: 'collapse',
            fontSize: 12,
            background: '#fff',
            border: '1px solid #e2e8f0',
          }}
        >
          <thead>
            <tr style={{ background: '#f8fafc' }}>
              <th style={th}>도메인</th>
              <th style={th}>IP</th>
              <th style={th}>Port</th>
              <th style={th}>Service</th>
              <th style={th}>Product</th>
              <th style={th}>Version</th>
            </tr>
          </thead>
          <tbody>
            {!(serviceScans || []).length ? (
              <tr>
                <td colSpan={6} style={{ ...td, color: '#94a3b8' }}>
                  없음
                </td>
              </tr>
            ) : (
              serviceScans.map((row) => {
                const hi = PDF_HIGH_RISK.has(row.port)
                return (
                  <tr
                    key={row.scan_id}
                    style={{ background: hi ? '#fffbeb' : undefined }}
                  >
                    <td style={td}>{row.domain || '—'}</td>
                    <td style={td}>{row.ip}</td>
                    <td style={td}>{row.port}</td>
                    <td style={td}>{row.service || '—'}</td>
                    <td style={td}>{row.product || '—'}</td>
                    <td style={td}>{row.version || '—'}</td>
                  </tr>
                )
              })
            )}
          </tbody>
        </table>
      </div>

      <h3 style={{ fontSize: 14, fontWeight: 600, margin: '12px 0 8px' }}>
        자산별 열린 포트 수
      </h3>
      <div style={{ width: '100%', height: 280 }}>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart
            data={summary.assets.map((a) => ({
              name:
                (a.name && a.name.length > 20
                  ? `${a.name.slice(0, 20)}…`
                  : a.name) || '—',
              openPorts: a.ports_count,
            }))}
            margin={{ bottom: 48, left: 8, right: 8, top: 8 }}
          >
            <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
            <XAxis
              dataKey="name"
              angle={-25}
              textAnchor="end"
              interval={0}
              height={56}
              tick={{ fontSize: 10 }}
            />
            <YAxis allowDecimals={false} />
            <Tooltip />
            <Bar dataKey="openPorts" fill="#0ea5e9" radius={[4, 4, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* 4. Service */}
      <SectionTitle>4. Service 분석</SectionTitle>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 24 }}>
        <div style={{ flex: '1 1 300px' }}>
          <h3 style={{ fontSize: 14, fontWeight: 600, marginBottom: 8 }}>
            OS 분포 (service_scans.os)
          </h3>
          <Donut
            data={(osDist || []).map((x) => ({ name: x.os, value: x.count }))}
            colors={{}}
          />
        </div>
        <div style={{ flex: '2 1 360px' }}>
          <h3 style={{ fontSize: 14, fontWeight: 600, marginBottom: 8 }}>
            제품 Top 10 (product)
          </h3>
          <div style={{ width: '100%', height: 280 }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                layout="vertical"
                data={(productTop || []).map((x) => ({
                  name: x.product?.length > 24 ? `${x.product.slice(0, 24)}…` : x.product,
                  c: x.count,
                }))}
                margin={{ left: 8, right: 16, top: 8, bottom: 8 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                <XAxis type="number" allowDecimals={false} />
                <YAxis type="category" dataKey="name" width={120} tick={{ fontSize: 10 }} />
                <Tooltip />
                <Bar dataKey="c" fill="#8b5cf6" radius={[0, 4, 4, 0]} name="건수" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <h3 style={{ fontSize: 14, fontWeight: 600, margin: '16px 0 8px' }}>
        HTTP Server 헤더 집계 (http_info_json → server)
      </h3>
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
          <thead>
            <tr style={{ background: '#f8fafc' }}>
              <th style={th}>Server</th>
              <th style={th}>건수</th>
            </tr>
          </thead>
          <tbody>
            {!(httpServers || []).length ? (
              <tr>
                <td colSpan={2} style={{ ...td, color: '#94a3b8' }}>
                  없음
                </td>
              </tr>
            ) : (
              httpServers.map((r) => (
                <tr key={r.server}>
                  <td style={td}>{r.server}</td>
                  <td style={td}>{r.count}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* 5. Vuln */}
      <SectionTitle>5. 취약점 탐지</SectionTitle>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 24 }}>
        <div style={{ flex: '1 1 300px' }}>
          <h3 style={{ fontSize: 14, fontWeight: 600, marginBottom: 8 }}>
            심각도 분포 (도넛, GROUP BY severity)
          </h3>
          {severityDonutData.length ? (
            <Donut data={severityDonutData} colors={VULN_COLORS} />
          ) : (
            <p style={{ color: '#94a3b8' }}>없음</p>
          )}
        </div>
        <div style={{ flex: '1 1 320px' }}>
          <h3 style={{ fontSize: 14, fontWeight: 600, marginBottom: 8 }}>
            탐지 출처별 건수
          </h3>
          <div style={{ width: '100%', height: 260 }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={(vulnStats?.by_source || []).map((s) => ({
                  name: s.source,
                  c: s.count,
                }))}
                margin={{ left: 8, right: 8, top: 8, bottom: 64 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                <XAxis dataKey="name" angle={-20} textAnchor="end" interval={0} height={70} tick={{ fontSize: 10 }} />
                <YAxis allowDecimals={false} />
                <Tooltip />
                <Bar dataKey="c" fill="#6366f1" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <h3 style={{ fontSize: 14, fontWeight: 600, margin: '16px 0 8px' }}>
        EPSS &gt; 0.7 고위험 목록
      </h3>
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
          <thead>
            <tr style={{ background: '#fef2f2' }}>
              <th style={th}>도메인</th>
              <th style={th}>IP:Port</th>
              <th style={th}>이름</th>
              <th style={th}>EPSS</th>
              <th style={th}>CVE</th>
            </tr>
          </thead>
          <tbody>
            {!(epssHigh || []).length ? (
              <tr>
                <td colSpan={5} style={{ ...td, color: '#94a3b8' }}>
                  해당 조건 없음
                </td>
              </tr>
            ) : (
              epssHigh.map((v) => (
                <tr key={v.vuln_id}>
                  <td style={td}>{v.domain || '—'}</td>
                  <td style={td}>
                    {v.ip}:{v.port}
                  </td>
                  <td style={td}>{v.name}</td>
                  <td style={td}>{v.epss != null ? v.epss.toFixed(3) : '—'}</td>
                  <td style={td}>{(v.cve_ids || []).join(', ') || '—'}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* 6. Exploit */}
      <SectionTitle>6. 교차검증 · 익스플로잇</SectionTitle>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 24, alignItems: 'flex-start' }}>
        <div style={{ flex: '1 1 280px' }}>
          <h3 style={{ fontSize: 14, fontWeight: 600, marginBottom: 8 }}>
            익스플로잇 결과 버킷 (JSON 휴리스틱)
          </h3>
          {exploitDonutData.length ? (
            <Donut data={exploitDonutData} colors={{}} />
          ) : (
            <p style={{ color: '#94a3b8' }}>없음</p>
          )}
        </div>
        <div style={{ flex: '1 1 260px' }}>
          <h3 style={{ fontSize: 14, fontWeight: 600, marginBottom: 8 }}>
            no_vuln_found 비율
          </h3>
          <div
            style={{
              background: '#fff',
              border: '1px solid #e2e8f0',
              borderRadius: 10,
              padding: 16,
            }}
          >
            <div style={{ fontSize: 36, fontWeight: 800 }}>
              {noVulnMetric?.no_vuln_rate_percent ?? 0}%
            </div>
            <div style={{ fontSize: 12, color: '#64748b', marginTop: 6 }}>
              {noVulnMetric?.no_vuln_rows ?? 0} / {noVulnMetric?.total_rows ?? 0}{' '}
              행
            </div>
          </div>
        </div>
      </div>

      <h3 style={{ fontSize: 14, fontWeight: 600, margin: '16px 0 8px' }}>
        익스플로잇 성공 추정 CVE Top
      </h3>
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
          <thead>
            <tr style={{ background: '#f8fafc' }}>
              <th style={th}>CVE</th>
              <th style={th}>건수</th>
            </tr>
          </thead>
          <tbody>
            {!(exploitTopCves || []).length ? (
              <tr>
                <td colSpan={2} style={{ ...td, color: '#94a3b8' }}>
                  없음
                </td>
              </tr>
            ) : (
              exploitTopCves.map((r) => (
                <tr key={r.cve_id}>
                  <td style={td}>{r.cve_id}</td>
                  <td style={td}>{r.count}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* 7. Remediation */}
      <SectionTitle>7. 대응 현황</SectionTitle>
      <h3 style={{ fontSize: 14, fontWeight: 600, margin: '0 0 8px' }}>
        고위험 취약점 우선순위 (critical/high, 익스 성공 우선 정렬)
      </h3>
      <div style={{ overflowX: 'auto', marginBottom: 20 }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
          <thead>
            <tr style={{ background: '#fef2f2' }}>
              <th style={th}>도메인</th>
              <th style={th}>IP:Port</th>
              <th style={th}>심각도</th>
              <th style={th}>CVSS</th>
              <th style={th}>이름</th>
              <th style={th}>exploit 요약</th>
            </tr>
          </thead>
          <tbody>
            {!(remediation || []).length ? (
              <tr>
                <td colSpan={6} style={{ ...td, color: '#94a3b8' }}>
                  없음
                </td>
              </tr>
            ) : (
              remediation.map((r) => (
                <tr key={r.vuln_id}>
                  <td style={td}>{r.domain || '—'}</td>
                  <td style={td}>
                    {r.ip}:{r.port}
                  </td>
                  <td style={td}>{r.severity}</td>
                  <td style={td}>{r.cvss_score ?? '—'}</td>
                  <td style={td}>{r.name}</td>
                  <td style={{ ...td, maxWidth: 220, wordBreak: 'break-all' }}>
                    {r.exploit_result_preview || '—'}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <h3 style={{ fontSize: 14, fontWeight: 600, margin: '0 0 8px' }}>
        자산별 위험 점수 (max CVSS + max EPSS×10)
      </h3>
      <div style={{ width: '100%', height: 300, marginBottom: 24 }}>
        {!riskRanking?.length ? (
          <p style={{ color: '#94a3b8' }}>없음</p>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <BarChart
              layout="vertical"
              data={riskRanking.map((x) => ({
                name: (x.domain || `asset ${x.asset_id}`).slice(0, 22),
                score: x.risk_score,
              }))}
              margin={{ left: 8, right: 16, top: 8, bottom: 8 }}
            >
              <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
              <XAxis type="number" />
              <YAxis type="category" dataKey="name" width={140} tick={{ fontSize: 10 }} />
              <Tooltip />
              <Bar dataKey="score" fill="#dc2626" radius={[0, 4, 4, 0]} name="점수" />
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>

      <h3 style={{ fontSize: 14, fontWeight: 600, margin: '0 0 8px' }}>
        도메인 × 심각도 히트맵 (셀 색 = 건수)
      </h3>
      <div style={{ overflowX: 'auto' }}>
        <table style={{ borderCollapse: 'collapse', fontSize: 11, minWidth: 520 }}>
          <thead>
            <tr>
              <th style={{ ...th, position: 'sticky', left: 0, background: '#f8fafc' }}>
                domain
              </th>
              {SEVERITY_ORDER.map((s) => (
                <th key={s} style={th}>
                  {s}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {!heatmap.rows.length ? (
              <tr>
                <td colSpan={1 + SEVERITY_ORDER.length} style={{ ...td, color: '#94a3b8' }}>
                  데이터 없음
                </td>
              </tr>
            ) : (
              heatmap.rows.map((row) => (
                <tr key={row.domain}>
                  <td
                    style={{
                      ...td,
                      position: 'sticky',
                      left: 0,
                      background: '#fff',
                      fontWeight: 600,
                    }}
                  >
                    {row.domain}
                  </td>
                  {SEVERITY_ORDER.map((s) => (
                    <td
                      key={s}
                      style={{
                        ...td,
                        textAlign: 'center',
                        background: heatColor(row[s], heatmap.maxC),
                        fontWeight: row[s] ? 600 : 400,
                      }}
                    >
                      {row[s] || ''}
                    </td>
                  ))}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </main>
  )
}
