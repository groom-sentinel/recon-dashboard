/** Backend origin for fetch calls (CRA: set REACT_APP_API_BASE_URL in .env). */
export function apiUrl(path) {
  const base =
    (typeof process !== 'undefined' &&
      process.env &&
      process.env.REACT_APP_API_BASE_URL) ||
    'http://127.0.0.1:8000'
  const normalized = String(base).replace(/\/$/, '')
  const p = path.startsWith('/') ? path : `/${path}`
  return `${normalized}${p}`
}
