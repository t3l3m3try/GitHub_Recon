/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  safelist: [
    'bg-red-500/20', 'text-red-300', 'border-red-500/60',
    'border-red-500/40', 'from-transparent', 'to-red-500/5', 'hover:border-red-400',

    'bg-orange-500/20', 'text-orange-300', 'border-orange-500/60',
    'border-orange-500/40', 'to-orange-500/5', 'hover:border-orange-400',

    'bg-yellow-500/20', 'text-yellow-300', 'border-yellow-500/60',
    'border-yellow-500/30', 'to-yellow-500/5', 'hover:border-yellow-400',

    'bg-cyan-500/20', 'text-cyan-300', 'border-cyan-500/60',
    'border-cyan-500/30', 'to-cyan-500/5', 'hover:border-cyan-400',

    'bg-gray-700/30', 'text-gray-300', 'border-gray-500/30',
    'border-gray-500/30', 'to-gray-500/5', 'hover:border-gray-400',

    'bg-black/50', 'border-purple-500/30', 'border-cyan-500/20',

    'bg-cyan-900/20', 'from-cyan-500/30', 'to-green-500/30',
    'bg-purple-900/20', 'from-purple-500/30', 'to-magenta-500/30'
  ],
  theme: {
    extend: {
      colors: {
        critical: '#D32F2F',
        high: '#F57C00',
        medium: '#FBC02D',
        low: '#1976D2',
        info: '#757575',
      }
    },
  },
  plugins: [],
}
