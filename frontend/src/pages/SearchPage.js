import { useState, useEffect, useRef } from 'react';
import Chart from 'chart.js/auto';

function Frame() {
  return (
    <div
      style={{
        backgroundColor: '#6ab4ff',
        width: '168px',
        height: '50px',
        borderRadius: '10px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '10px 37px',
        boxSizing: 'border-box',
      }}
    >
      <p
        style={{
          margin: 0,
          fontFamily: "'Inria Sans', 'Noto Sans KR', sans-serif",
          fontSize: '24px',
          lineHeight: 'normal',
          color: '#000',
        }}
      >
        스캔 시작
      </p>
    </div>
  );
}

function Frame1({ target, setTarget, onSubmit, loading }) {
  return (
    <div
      style={{
        width: '100%',
        height: '66px',
        backgroundColor: '#fff',
        position: 'relative',
        boxSizing: 'border-box',
      }}
    >
      <div
        aria-hidden="true"
        style={{
          position: 'absolute',
          inset: 0,
          border: '1px solid #505050',
          boxSizing: 'border-box',
          pointerEvents: 'none',
        }}
      />
      <form
        onSubmit={onSubmit}
        style={{
          position: 'absolute',
          inset: 0,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '8px 18px',
          boxSizing: 'border-box',
        }}
      >
        <input
          value={target}
          onChange={e => setTarget(e.target.value)}
          placeholder="예: scanme.nmap.org"
          style={{
            width: '100%',
            height: '50px',
            borderRadius: '8px',
            border: '1px solid #d1d5db',
            padding: '0 14px',
            fontSize: '16px',
            fontFamily: "'Noto Sans KR', sans-serif",
            outline: 'none',
            boxSizing: 'border-box',
          }}
        />
        <button
          type="submit"
          disabled={loading}
          style={{
            marginLeft: '16px',
            background: 'transparent',
            border: 'none',
            padding: 0,
            cursor: loading ? 'default' : 'pointer',
          }}
        >
          <Frame />
        </button>
      </form>
    </div>
  );
}

export default function Frame2() {
  const [target, setTarget] = useState('');
  const [scanData, setScanData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const assetChartRef = useRef(null);
  const vulnChartRef  = useRef(null);
  const riskChartRef  = useRef(null);


  const handleScan = async event => {
    event.preventDefault();
    setError('');
    setScanData(null);
    if (!target.trim()) {
      setError('IP 주소 또는 도메인을 입력하세요.');
      return;
    }

    setLoading(true);
    try {
      const response = await fetch('http://127.0.0.1:8000/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target })
      });
      const data = await response.json();
      setScanData(data);
      //const response = await fetch(`/api/scan?target=${encodeURIComponent(target)}`);
      //if (!response.ok) {
      //  throw new Error(`HTTP ${response.status}`);
      //}
      //const data = await response.json();
      //setScanData(data);
    } catch (err) {
      console.error(err);
      setError('⚠ 스캔 중 오류가 발생했습니다.');
    } finally {
      setLoading(false);
    }
  };

 useEffect(() => {
  if (!scanData) return;

  // 1) 자산 차트 데이터
  new Chart(assetChartRef.current, {
    type: 'bar',
    data: {
      labels: ['Assets'],
      datasets: [{
        label: '개수',
        data: [scanData.assets.length],
        backgroundColor: ['#35607b']
      }]
    },
    options: { indexAxis: 'y' }
  });

  // 2) 취약점 심각도 데이터 세기
  const counts = { low:0, medium:0, high:0 };
  scanData.vulnerabilities.forEach(v => {
    if (counts[v.severity] !== undefined) counts[v.severity]++;
  });
  new Chart(vulnChartRef.current, {
    type: 'pie',
    data: {
      labels: ['low','medium','high'],
      datasets: [{
        data: [counts.low, counts.medium, counts.high],
        backgroundColor: ['green','orange','red']
      }]
    }
  });

  // 3) 위험도 분포 세기
  const rcounts = { safe:0, warning:0, danger:0 };
  scanData.risks.forEach(r => {
    if (rcounts[r.level] !== undefined) rcounts[r.level]++;
  });
  new Chart(riskChartRef.current, {
    type: 'doughnut',
    data: {
      labels: ['safe','warning','danger'],
      datasets: [{
        data: [rcounts.safe, rcounts.warning, rcounts.danger],
        backgroundColor: ['skyblue','gold','crimson']
      }]
    }
  });

 }, [scanData]);


  return (
    <div
      style={{
        width: '100%',
        height: '100%',
        padding: '20px 37px',
        display: 'flex',
        flexDirection: 'column',
        gap: '9px',
        boxSizing: 'border-box',
      }}
    >
      <div
        style={{
          display: 'flex',
          flexDirection: 'column',
          gap: '9px',
          width: '100%',
        }}
      >
        <div
          style={{
            display: 'flex',
            gap: '9px',
            flexDirection: 'column',
            width: '100%',
          }}
        >
          <div
            style={{
              display: 'flex',
              flexDirection: 'column',
              gap: '2px',
            }}
          >
            <p
              style={{
                margin: 0,
                fontFamily: "'Inria Sans', 'Noto Sans KR', sans-serif",
                fontSize: '24px',
                lineHeight: 'normal',
                color: '#000',
              }}
            >
              IP 주소 또는 도메인 입력:
            </p>
            <p
              style={{
                margin: 0,
                fontFamily: "'Intel One Mono', monospace",
                fontSize: '14px',
                color: '#6b7280',
              }}
            >
              127.0.0.1, example.com 등 입력 후 스캔을 시작하세요.
            </p>
          </div>
          <Frame1
            target={target}
            setTarget={setTarget}
            onSubmit={handleScan}
            loading={loading}
          />
        </div>
      </div>
      {error ? (
        <p style={{ margin: 0, color: '#dc2626', fontSize: '14px' }}>{error}</p>
      ) : null}
      <div style={{ width: '100%' }}>
        <p
          style={{
            margin: '0 0 6px 0',
            fontFamily: "'Inria Sans', 'Noto Sans KR', sans-serif",
            fontSize: '24px',
            lineHeight: 'normal',
            color: '#000',
          }}
        >
          결과 확인:
        </p>
        <div
          style={{
            width: '100%',
            height: '303px',
            backgroundColor: '#fff',
            position: 'relative',
            boxSizing: 'border-box',
          }}
        >
          <div
            aria-hidden="true"
            style={{
              position: 'absolute',
              inset: 0,
              border: '1px solid #676767',
              boxSizing: 'border-box',
              pointerEvents: 'none',
            }}
          />
          {scanData ? (
            <div
              style={{
                position: 'relative',
                padding: '18px',
                color: '#111827',
                fontFamily: "'Noto Sans KR', sans-serif",
                fontSize: '14px',
                overflow: 'auto',
                height: '100%',
                boxSizing: 'border-box',
              }}
            >
               {/* 자산 수 막대그래프 */}
                <h3>자산(Assets) 개수</h3>
                <canvas ref={assetChartRef} />

               {/* 취약점 심각도 파이차트 */}
               <h3>취약점(Vulnerabilities) 심각도</h3>
               <canvas ref={vulnChartRef} />

               {/* 위험도(Risks) 도넛차트 */}
               <h3>위험도(Risks) 분포</h3>
               <canvas ref={riskChartRef} />
            {/* <pre style={{ margin: 0, whiteSpace: 'pre-wrap' }}>
                {JSON.stringify(scanData, null, 2)}
              </pre> */}
            </div>
          ) : (
            <div
              style={{
                position: 'relative',
                width: '100%',
                height: '100%',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#6b7280',
                fontFamily: "'Noto Sans KR', sans-serif",
                fontSize: '16px',
              }}
            >
              스캔 결과가 여기에 표시됩니다.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

