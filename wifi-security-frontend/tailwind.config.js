/** @type {import('tailwindcss').Config} */
module.exports = {
    content: [
        './src/**/*.{js,jsx,ts,tsx}',
        './public/index.html',
    ],
    theme: {
        extend: {
            colors: {
                primary: {
                    DEFAULT: '#2563eb',
                    dark: '#1d4ed8',
                    light: '#3b82f6',
                },
                secondary: {
                    DEFAULT: '#64748b',
                    dark: '#475569',
                    light: '#94a3b8',
                },
                success: {
                    DEFAULT: '#05cd99',
                    dark: '#04b386',
                    light: '#10ffc7',
                },
                danger: {
                    DEFAULT: '#ff5b5b',
                    dark: '#e53e3e',
                    light: '#ff8a8a',
                },
                warning: {
                    DEFAULT: '#fbbf24',
                    dark: '#f59e0b',
                    light: '#fcd34d',
                },
            },
            fontFamily: {
                sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
                display: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
                mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
            },
            fontSize: {
                'h1': ['2.5rem', { lineHeight: '1.2', fontWeight: '700' }],
                'h2': ['2rem', { lineHeight: '1.3', fontWeight: '600' }],
                'h3': ['1.5rem', { lineHeight: '1.4', fontWeight: '600' }],
                'h4': ['1.25rem', { lineHeight: '1.5', fontWeight: '500' }],
            },
            borderRadius: {
                'button': '0.75rem',
                'card': '1rem',
                'input': '0.625rem',
                'panel': '1.5rem',
            },
            boxShadow: {
                'panel': '0 25px 50px -12px rgba(0, 0, 0, 0.15)',
                'card': '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
                'button-blue': '0 4px 14px 0 rgba(37, 99, 235, 0.39)',
                'button-blue-hover': '0 6px 20px rgba(37, 99, 235, 0.5)',
                'input-focus': '0 0 0 3px rgba(37, 99, 235, 0.15)',
            },
            backgroundImage: {
                'gradient-royal': 'linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%)',
                'gradient-radial': 'radial-gradient(ellipse at center, var(--tw-gradient-stops))',
            },
            transitionDuration: {
                'hover': '200ms',
                'focus': '150ms',
                'form': '300ms',
            },
            animation: {
                'fade-in': 'fadeIn 0.3s ease-out',
                'slide-up': 'slideUp 0.3s ease-out',
                'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
            },
            keyframes: {
                fadeIn: {
                    '0%': { opacity: '0' },
                    '100%': { opacity: '1' },
                },
                slideUp: {
                    '0%': { opacity: '0', transform: 'translateY(10px)' },
                    '100%': { opacity: '1', transform: 'translateY(0)' },
                },
            },
        },
    },
    plugins: [],
};
