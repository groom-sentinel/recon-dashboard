import { useState } from 'react';

function Frame() {
  return (
    <div
      style={{
        backgroundColor: '#6ab4ff',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '10px 37px',
        borderRadius: '10px',
        width: '168px',
        height: '50px',
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
          whiteSpace: 'nowrap',
        }}
      >
        스캔 시작
      </p>
    </div>
  );
}

function Frame1({ onSubmit, target, setTarget, loading }) {
  return (
    <div
      style={{
        backgroundColor: '#fff',
        height: '66px',
        position: 'relative',
        width: '100%',
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
          position: 'relative',
          width: '100%',
          height: '100%',
        }}
      >
        <input
          type="text"
          value={target}
          onChange={e => setTarget(e.target.value)}
          placeholder="예: scanme.nmap.org"
          style={{
            position: 'absolute',
            left: '18px',
            top: '8px',
            height: '50px',
            width: '580px',
            backgroundColor: 'transparent',
            outline: 'none',
            border: '1px solid #d1d5db',
            borderRadius: '8px',
            padding: '0 12px',
            fontSize: '16px',
            fontFamily: "'Noto Sans KR', sans-serif",
            boxSizing: 'border-box',
          }}
        />
        <button
          type="submit"
          disabled={loading}
          style={{
            position: 'absolute',
            right: '18px',
            top: '8px',
            padding: 0,
            border: 'none',
            background: 'transparent',
            cursor: 'pointer',
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

  const handleScan = async e => {
    e.preventDefault();
    setError('');
    setScanData(null);
    if (!target.trim()) {
      setError('IP 주소 또는 도메인을 입력하세요.');
      return;
    }
    setLoading(true);
    try {
      const res = await fetch(`/api/scan?target=${encodeURIComponent(target)}`);
      if (!res.ok) throw new Error(res.statusText);
      const json = await res.json();
      setScanData(json);
    } catch (e) {
      console.error(e);
      setError('스캔 중 오류가 발생했습니다.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: '9px',
        alignItems: 'flex-start',
        position: 'relative',
        width: '100%',
        boxSizing: 'border-box',
        padding: '20px 37px',
      }}
    >
      <p
        style={{
          margin: 0,
          fontFamily: "'Intel One Mono', 'Noto Sans KR', sans-serif",
          fontWeight: 600,
          lineHeight: 0,
          fontSize: '0px',
          color: '#000',
          width: '100%',
        }}
      >
        <span
          style={{
            display: 'inline-block',
            fontFamily: "'Inria Sans', 'Noto Sans KR', sans-serif",
            lineHeight: 'normal',
            fontSize: '24px',
            fontVariationSettings: "'wght' 400",
            color: '#000',
          }}
        >
          IP 주소 또는 도메인 입력:
        </span>
        <span
          style={{
            display: 'inline-block',
            lineHeight: 'normal',
            fontSize: '64px',
            color: 'transparent',
          }}
        >
          {' '}
        </span>
      </p>
      <Frame1 onSubmit={handleScan} target={target} setTarget={setTarget} loading={loading} />
      {error && (
        <p style={{ margin: 0, color: '#dc2626', fontSize: '14px' }}>⚠ {error}</p>
      )}
      <p
        style={{
          margin: 0,
          fontFamily: "'Inria Sans', 'Noto Sans KR', sans-serif",
          lineHeight: 'normal',
          fontSize: '24px',
          fontVariationSettings: "'wght' 400",
          color: '#000',
        }}
      >
        결과 확인:
      </p>
      <div
        style={{
          backgroundColor: '#fff',
          height: '303px',
          width: '100%',
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
      </div>
    </div>
  );
}
