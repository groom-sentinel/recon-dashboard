// components/AssetCard.jsx
import React from 'react'

const RISK_BADGE = {
  danger:  { bg: '#fef2f2', border: '#fca5a5', text: '#dc2626', label: '위험' },
  warning: { bg: '#fffbeb', border: '#fcd34d', text: '#d97706', label: '주의' },
  safe:    { bg: '#f0fdf4', border: '#86efac', text: '#16a34a', label: '양호' },
}

/**
 * 자산 카드 — 보안팀 즉시 활용용.
 *
 * Props:
 *   asset: {
 *     id, ip, name (domain), risk_level, category,
 *     tech_stack: string[], recommendations: string[],
 *     open_ports: number[], scanned_at: string|null
 *   }
 */
export default function AssetCard({ asset }) {
  const badge = RISK_BADGE[asset.risk_level] || RISK_BADGE.safe

  return (
    <div
      style={{
        background: '#fff',
        border: `1px solid ${badge.border}`,
        borderRadius: 12,
        padding: '18px 20px',
        boxShadow: '0 2px 8px rgba(0,0,0,0.06)',
        display: 'flex',
        flexDirection: 'column',
        gap: 10,
        fontFamily: 'system-ui, sans-serif',
        minWidth: 0,
      }}
    >
      {/* 헤더: IP + 위험도 배지 */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 8 }}>
        <div>
          <div style={{ fontSize: 18, fontWeight: 800, color: '#0f172a', lineHeight: 1.2 }}>
            {asset.ip || '—'}
          </div>
          {asset.name && (
            <div style={{ fontSize: 12, color: '#64748b', marginTop: 2 }}>
              {asset.name}
            </div>
          )}
        </div>
        <span
          style={{
            background: badge.bg,
            color: badge.text,
            border: `1px solid ${badge.border}`,
            borderRadius: 6,
            padding: '2px 10px',
            fontSize: 12,
            fontWeight: 700,
            whiteSpace: 'nowrap',
            flexShrink: 0,
          }}
        >
          {badge.label}
        </span>
      </div>

      {/* 분류 */}
      <Row label="분류" value={asset.category || '—'} />

      {/* 기술 스택 */}
      <div>
        <Label>기술 스택</Label>
        {asset.tech_stack && asset.tech_stack.length > 0 ? (
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 4 }}>
            {asset.tech_stack.map((t, i) => (
              <span
                key={i}
                style={{
                  background: '#f1f5f9',
                  color: '#334155',
                  borderRadius: 4,
                  padding: '2px 8px',
                  fontSize: 11,
                  fontWeight: 600,
                }}
              >
                {t}
              </span>
            ))}
          </div>
        ) : (
          <Value>—</Value>
        )}
      </div>

      {/* 열린 포트 */}
      {asset.open_ports && asset.open_ports.length > 0 && (
        <div>
          <Label>열린 포트</Label>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 4 }}>
            {asset.open_ports.map((p) => (
              <span
                key={p}
                style={{
                  background: [22, 23, 3389, 3306, 5432, 6379].includes(p)
                    ? '#fef2f2'
                    : '#f8fafc',
                  color: [22, 23, 3389, 3306, 5432, 6379].includes(p)
                    ? '#dc2626'
                    : '#475569',
                  border: '1px solid #e2e8f0',
                  borderRadius: 4,
                  padding: '1px 7px',
                  fontSize: 11,
                  fontFamily: 'monospace',
                  fontWeight: 600,
                }}
              >
                {p}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* 권장 조치 */}
      <div>
        <Label>권장 조치</Label>
        {asset.recommendations && asset.recommendations.length > 0 ? (
          <ol style={{ margin: '4px 0 0', paddingLeft: 18 }}>
            {asset.recommendations.map((r, i) => (
              <li key={i} style={{ fontSize: 12, color: '#1e293b', marginBottom: 3, lineHeight: 1.4 }}>
                {r}
              </li>
            ))}
          </ol>
        ) : (
          <Value style={{ color: '#16a34a' }}>조치 필요 항목 없음</Value>
        )}
      </div>

      {/* 스캔 시각 */}
      {asset.scanned_at && (
        <div style={{ fontSize: 11, color: '#94a3b8', textAlign: 'right', marginTop: 4 }}>
          스캔: {asset.scanned_at.slice(0, 16).replace('T', ' ')}
        </div>
      )}
    </div>
  )
}

function Label({ children }) {
  return (
    <div style={{ fontSize: 11, fontWeight: 700, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
      {children}
    </div>
  )
}

function Value({ children, style }) {
  return (
    <div style={{ fontSize: 13, color: '#334155', marginTop: 2, ...style }}>
      {children}
    </div>
  )
}

function Row({ label, value }) {
  return (
    <div>
      <Label>{label}</Label>
      <Value>{value}</Value>
    </div>
  )
}
