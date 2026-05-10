// src/pages/DashboardPage.jsx
import React, { useEffect, useState } from 'react'
import {
  ResponsiveContainer,
  PieChart, Pie, Cell,
  BarChart, Bar, XAxis, YAxis, Tooltip
} from 'recharts'
import { loadDashboardData } from '../api/dashboard'

export default function DashboardPage() {
  const [data, setData]     = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState('')

  useEffect(() => {
    ;(async () => {
      setLoading(true)
      try {
        const d = await loadDashboardData()
        setData(d)
      } catch (e) {
        setError(e.message)
      } finally {
        setLoading(false)
      }
    })()
  }, [])

  if (loading) return <p style={{ textAlign:'center', padding:'40px' }}>불러오는 중…</p>
  if (error)   return <p style={{ textAlign:'center', color:'red' }}>{error}</p>

  const { summary, riskCounts, vulnCounts } = data

  // PieChart 용 배열 변환
  const riskPieData = Object.entries(riskCounts)
    .map(([k,v]) => ({ name:k, value:v }))
    .filter(x => x.value > 0)

  const vulnPieData = Object.entries(vulnCounts)
    .map(([k,v]) => ({ name:k, value:v }))
    .filter(x => x.value > 0)

  return (
    <main style={{ maxWidth: '960px', margin:'0 auto', padding:'20px', fontFamily:'sans-serif' }}>
      <h1 style={{ fontSize: '32px', fontWeight:'bold', marginBottom:'24px' }}>
        포트스캐너 대시보드
      </h1>

      {/* 포트 스캔 테이블 */}
      <div style={{ marginBottom:'24px' }}>
        <h3 style={{ margin:'0 0 12px', fontSize:18, fontWeight:600 }}>
          포트 스캔 결과
        </h3>
        <table style={{ width:'100%', borderCollapse:'collapse' }}>
          <thead>
            <tr style={{ background:'#f3f4f6' }}>
              <th style={{ border:'1px solid #ddd', padding:8 }}>Port</th>
              <th style={{ border:'1px solid #ddd', padding:8 }}>Service</th>
              <th style={{ border:'1px solid #ddd', padding:8 }}>Version</th>
            </tr>
          </thead>
          <tbody>
            {summary.assets.map((a, idx) => (
              <tr key={idx} style={idx%2?{background:'#fafafa'}:{}}>
                <td style={{ border:'1px solid #ddd', padding:8 }}>
                  {a.ports_count}
                </td>
                <td style={{ border:'1px solid #ddd', padding:8 }}>
                  {a.name}
                </td>
                <td style={{ border:'1px solid #ddd', padding:8 }}>
                  {/* 예시 컬럼 */}
                  —
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* 요약 카드 */}
      <div style={{ display:'flex', gap:'16px', marginBottom:'32px' }}>
        {/* 전체 자산 수 */}
        <div style={{
          flex:1, background:'#fff',
          boxShadow:'0 2px 6px rgba(0,0,0,0.1)',
          borderRadius:8, padding:16
        }}>
          <p style={{ margin:0, color:'#666', fontSize:14 }}>전체 자산 수</p>
          <p style={{ margin:'8px 0 0', fontSize:28, fontWeight:'bold' }}>
            {summary.total_assets}
          </p>
        </div>
        {/* 위험 자산 수 */}
        <div style={{
          flex:1, background:'#fff',
          boxShadow:'0 2px 6px rgba(0,0,0,0.1)',
          borderRadius:8, padding:16
        }}>
          <p style={{ margin:0, color:'#666', fontSize:14 }}>위험 자산 수</p>
          <p style={{ margin:'8px 0 0', fontSize:28, fontWeight:'bold' }}>
            {summary.risky_assets}
          </p>
        </div>
        {/* Critical CVE 건수 */}
        <div style={{
          flex:1, background:'#fff',
          boxShadow:'0 2px 6px rgba(0,0,0,0.1)',
          borderRadius:8, padding:16
        }}>
          <p style={{ margin:0, color:'#666', fontSize:14 }}>Critical CVE 건수</p>
          <p style={{ margin:'8px 0 0', fontSize:28, fontWeight:'bold' }}>
            {summary.critical_cves}
          </p>
        </div>
      </div>

      <div
        style={{
          display: 'flex',
          gap: '32px',         // 차트 사이 간격
          marginBottom: '32px' // 아래 여백
        }}
      >
        {/* 1) 위험도 분포 */}
        <div style={{ flex: 1 }}>
          <h3 style={{ margin: '0 0 16px', fontSize: 18, fontWeight: 600 }}>
            위험도 분포
          </h3>
          <div style={{ width: '100%', height: 250 }}>
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={riskPieData}
                  dataKey="value"
                  nameKey="name"
                  outerRadius={80}
                  label={e => `${e.name}: ${e.value}`}
                >
                  {riskPieData.map((e, i) => (
                    <Cell
                      key={i}
                      fill={
                        e.name === 'safe'
                          ? '#60a5fa'
                         : e.name === 'warning'
                          ? '#facc15'
                          : '#ef4444'
                      }
                   />
                  ))}
               </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
         </div>
       </div>

        {/* 2) 취약점 심각도 분포 */}
        <div style={{ flex: 1 }}>
          <h3 style={{ margin: '0 0 16px', fontSize: 18, fontWeight: 600 }}>
            취약점 심각도 분포  
          </h3>
          <div style={{ width: '100%', height: 250 }}>
            <ResponsiveContainer width="100%" height="100%">
             <PieChart>
                <Pie
                  data={vulnPieData}
                  dataKey="value"
                  nameKey="name"
                  outerRadius={80}
                  label={e => `${e.name}: ${e.value}`}
               >
                  {vulnPieData.map((e, i) => (
                    <Cell
                      key={i}
                      fill={
                        e.name === 'low'
                          ? '#10b981'
                          : e.name === 'medium'
                         ? '#f59e0b'
                         : '#ef4444'
                     }
                   />
                 ))}
                </Pie>
               <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* 자산별 열린 포트 수 */}
      <div style={{ marginBottom:'32px' }}>
        <h3 style={{ margin:'0 0 16px', fontSize:18, fontWeight:600 }}>
          자산별 열린 포트 수
        </h3>
        <div style={{ width:'100%', height:300 }}>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart
              data={summary.assets.map(a => ({
                name: a.name,
                openPorts: a.ports_count
              }))}
            >
              <XAxis dataKey="name" />
              <YAxis allowDecimals={false} />
              <Tooltip />
              <Bar dataKey="openPorts" fill="#3b82f6" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </main>
  )
}