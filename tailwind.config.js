/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class',
  // Só arquivos que realmente geram classes no HTML. Varrer todo apps/**/*.py fazia
  // palavras de testes e docstrings (ex.: "container") virarem CSS em produção.
  content: [
    './templates/**/*.html',
    './apps/**/forms.py',
    './static/js/**/*.js',
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
      colors: {
        brand: {
          50: '#f0f9ff',
          100: '#e0f2fe',
          400: '#38bdf8',
          500: '#0ea5e9',
          600: '#0284c7',
          700: '#0369a1',
          900: '#0c4a6e',
        }
      }
    },
  },
  plugins: [],
}
