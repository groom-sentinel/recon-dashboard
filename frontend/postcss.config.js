// postcss.config.js
module.exports = {
  plugins: {
    // 바뀐 플러그인 이름으로 등록
    '@tailwindcss/postcss': {},
    // autoprefixer도 같이 둡니다
    autoprefixer: {},
  }
}