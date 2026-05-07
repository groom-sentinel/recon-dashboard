// tailwind.config.js
/** @type {import('tailwindcss').Config} */
module.exports = {
    content: ['./src/**/*.{js,jsx,ts,tsx,html}'],
    theme: {
        extend: {
            fontFamily: {
                inter: ['Inter', 'sans-serif'],
                noto: ['Noto Sans KR', 'sans-serif'],
                allerta: ['Allerta Stencil', 'sans-serif'],
            },
        },
    },
    plugins: [],
}