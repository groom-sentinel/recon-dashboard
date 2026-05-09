import React from 'react';
import { useNavigate } from 'react-router-dom';
import './Hero.css';


export default function Hero() {
  const navigate = useNavigate();

  const handleSearch = () => {
    navigate('/search');
  };

return (
    <main className="hero">
      <div className="hero__title-wrapper">
        <h1 className="hero__title-main">도메인의 포트 정보를 확인하세요</h1>
        <div className="hero__title-by-row">
        </div>
      </div>

      <p className="hero__description">
        네트워크 사기꾼들로부터 PC 보호 수준을 결정하기 위해서는 열린 포트를 확인해야 합니다. 포트가 열려 있을 경우, 맬웨어에 감염되거나 PC에 원격으로 접근될 위험이 커집니다. 이로 인해 사용자의 개인정보 유출 위험이 높아질 수 있습니다. 이러한 위험을 방지하려면, 외부에서 포트에 접근 가능한지 확인해야 합니다.
      </p>

      <div className="hero__search-wrapper">
        <form
          onSubmit={handleSearch}
          className={'hero__search-form'}
        >
          <p className="hero__search-message">
            스캔시작을 누르시면 검색페이지로 이동합니다
          </p>
          <button type="submit" className="hero__search-btn">
            스캔시작
          </button>
        </form>
      </div>
    </main>
  );
}

