import React, { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';

// ── Animated counter hook ─────────────────────────────────────────────────────
function useCounter(target: number, duration = 1800) {
    const [count, setCount] = useState(0);
    useEffect(() => {
        let start = 0;
        const step = Math.ceil(target / (duration / 16));
        const timer = setInterval(() => {
            start += step;
            if (start >= target) { setCount(target); clearInterval(timer); }
            else setCount(start);
        }, 16);
        return () => clearInterval(timer);
    }, [target, duration]);
    return count;
}

// ── WiFi Shield SVG Icon ──────────────────────────────────────────────────────
const ShieldWifiIcon: React.FC<{ className?: string }> = ({ className }) => (
    <svg className={className} viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M32 4L8 14v18c0 14.4 10.4 26.4 24 30 13.6-3.6 24-15.6 24-30V14L32 4z"
            stroke="currentColor" strokeWidth="2.5" fill="rgba(37,99,235,0.12)" />
        <g transform="translate(32, 38)">
            <circle cx="0" cy="8" r="3" fill="currentColor" />
            <path d="M-6 2a8.5 8.5 0 0 1 12 0" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" fill="none" />
            <path d="M-12 -4a15 15 0 0 1 24 0" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" fill="none" />
            <path d="M-18 -10a22 22 0 0 1 36 0" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" fill="none" />
        </g>
    </svg>
);

// ── Feature data ──────────────────────────────────────────────────────────────
const FEATURES = [
    {
        icon: '🛡️',
        title: 'Kernel-Level XDP Filtering',
        desc: 'Microsecond-speed interception of Wi-Fi deauth frames before they reach the OS network stack.',
    },
    {
        icon: '🤖',
        title: 'AI Anomaly Detection',
        desc: 'Dual-layer ML pipeline delivers real-time confidence scores to confirm zero-day attacks.',
    },
    {
        icon: '🔗',
        title: 'Kill Chain Tracking',
        desc: 'Persistent attacker state machine escalates defenses automatically as threat scores rise.',
    },
    {
        icon: '🔔',
        title: 'Real-Time Alerts',
        desc: 'Instant push notifications via SSE dashboard feed with throttled email alerts per attacker.',
    },
    {
        icon: '📡',
        title: 'Client Scanner',
        desc: 'Continuously scans and identifies all devices on your network with vendor lookup.',
    },
    {
        icon: '📊',
        title: 'Rich Analytics Dashboard',
        desc: 'Full attack history, detection stats, and ML confidence scores visualized in real time.',
    },
];

// ── Terminal log lines ────────────────────────────────────────────────────────
const LOG_LINES = [
    { text: '> DEFENSE SYSTEM INITIALIZED', color: 'text-blue-500' },
    { text: '> XDP PROGRAM LOADED ON wlan0', color: 'text-green-600' },
    { text: '> KILL CHAIN STATE MACHINE READY', color: 'text-blue-400' },
    { text: '> [BLOCK] DEAUTH frame — 00:1A:2B:3C:4D:5E DROPPED', color: 'text-red-500' },
    { text: '> [ML]    Anomaly score: 0.94 — ATTACK CONFIRMED', color: 'text-amber-600' },
    { text: '> [ALERT] Email dispatched to admin@institute.edu', color: 'text-purple-500' },
    { text: '> [BLOCK] Repeat attacker — escalation level 3', color: 'text-red-500' },
    { text: '> [OK]    Client connectivity preserved ✓', color: 'text-green-600' },
];

// ── Main Component ────────────────────────────────────────────────────────────
export const LandingPage: React.FC = () => {
    const threatsCount = useCounter(24198);
    const devicesCount = useCounter(312);
    const uptimeCount = useCounter(99);

    const [visibleLines, setVisibleLines] = useState(1);
    const terminalRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        const interval = setInterval(() => {
            setVisibleLines(prev => (prev >= LOG_LINES.length ? 1 : prev + 1));
        }, 1100);
        return () => clearInterval(interval);
    }, []);

    useEffect(() => {
        if (terminalRef.current) {
            terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
        }
    }, [visibleLines]);

    return (
        <div className="min-h-screen bg-white text-slate-900 overflow-x-hidden">

            {/* ── Navbar ── */}
            <header className="sticky top-0 z-50 bg-white/90 backdrop-blur border-b border-slate-100 shadow-sm">
                <nav className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
                    <div className="flex items-center gap-2.5">
                        <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-blue-600 shadow-md">
                            <ShieldWifiIcon className="w-5 h-5 text-white" />
                        </div>
                        <span className="text-lg font-bold tracking-[0.15em] text-blue-700 uppercase font-mono">
                            WiFi Shield
                        </span>
                    </div>

                    <div className="hidden md:flex items-center gap-8 text-[11px] font-semibold text-slate-500 uppercase tracking-[0.2em] font-mono">
                        <a href="#features" className="hover:text-blue-600 transition-colors">Features</a>
                        <a href="#console" className="hover:text-blue-600 transition-colors">Console</a>
                        <a href="#stats" className="hover:text-blue-600 transition-colors">Stats</a>
                    </div>

                    <div className="flex items-center gap-3">
                        <Link
                            to="/login"
                            className="px-4 py-2 text-sm font-semibold text-blue-600 border border-blue-200 rounded-xl hover:bg-blue-50 transition-all"
                        >
                            Sign In
                        </Link>
                        <Link
                            to="/register"
                            className="px-4 py-2 text-sm font-semibold bg-blue-600 hover:bg-blue-700 text-white rounded-xl shadow-md hover:shadow-lg transition-all"
                        >
                            Get Started
                        </Link>
                    </div>
                </nav>
            </header>

            {/* ── Hero Section ── */}
            <section className="max-w-7xl mx-auto px-6 pt-16 pb-12 lg:pt-24 grid lg:grid-cols-2 gap-12 items-center">
                {/* Left — Copy */}
                <div>
                    <div className="inline-flex items-center gap-2 px-3 py-1.5 mb-6 rounded-full border border-blue-200 bg-blue-50 text-blue-600 text-[11px] font-semibold uppercase tracking-[0.2em] font-mono">
                        <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
                        System Operational · Monitoring Active
                    </div>

                    <h1 className="text-5xl lg:text-6xl font-extrabold leading-tight mb-6 text-slate-900 tracking-tight">
                        WiFi{' '}
                        <span className="text-blue-600">Security</span>
                        <br />
                        Made Simple.
                    </h1>

                    <p className="text-lg text-slate-500 leading-relaxed mb-8 max-w-lg">
                        AI-powered, kernel-level protection against deauthentication attacks,
                        unauthorized access, and WiFi spoofing — all monitored from a single
                        real-time dashboard.
                    </p>

                    <div className="flex flex-wrap gap-4">
                        <Link
                            to="/register"
                            className="inline-flex items-center gap-2 px-6 py-3.5 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-2xl shadow-lg hover:shadow-xl transition-all hover:scale-105 active:scale-95"
                        >
                            Get Started Free
                            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                <path strokeLinecap="round" strokeLinejoin="round" d="M14 5l7 7m0 0l-7 7m7-7H3" />
                            </svg>
                        </Link>
                        <Link
                            to="/login"
                            className="inline-flex items-center gap-2 px-6 py-3.5 border-2 border-slate-200 text-slate-600 hover:border-blue-300 hover:text-blue-600 font-semibold rounded-2xl transition-all hover:scale-105 active:scale-95"
                        >
                            Sign In
                        </Link>
                    </div>
                </div>

                {/* Right — Hero Image */}
                <div className="relative flex items-center justify-center">
                    {/* Soft blob behind image */}
                    <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
                        <div className="w-[600px] h-[600px] rounded-full bg-blue-100/80 blur-3xl" />
                    </div>
                    <img
                        src="/hero-security.png"
                        alt="WiFi Security Monitoring"
                        className="relative z-10 w-full lg:scale-150 drop-shadow-xl"
                    />
                </div>
            </section>

            {/* ── Stats Bar ── */}
            <section id="stats" className="bg-blue-600 text-white">
                <div className="max-w-7xl mx-auto px-6 py-8 grid grid-cols-1 sm:grid-cols-3 gap-6 text-center">
                    <div>
                        <div className="text-blue-200 text-[11px] font-semibold uppercase tracking-[0.2em] font-mono mb-1 flex items-center justify-center gap-2">
                            <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
                            System Status
                        </div>
                        <div className="text-3xl font-extrabold font-mono tracking-[0.1em]">SECURE</div>
                    </div>
                    <div>
                        <div className="text-blue-200 text-[11px] font-semibold uppercase tracking-[0.2em] font-mono mb-1">Threats Blocked</div>
                        <div className="text-3xl font-extrabold font-mono">{threatsCount.toLocaleString()}</div>
                    </div>
                    <div>
                        <div className="text-blue-200 text-[11px] font-semibold uppercase tracking-[0.2em] font-mono mb-1">Platform Uptime</div>
                        <div className="text-3xl font-extrabold font-mono">{uptimeCount}%</div>
                    </div>
                </div>
            </section>

            {/* ── Features Grid ── */}
            <section id="features" className="bg-slate-50 py-20">
                <div className="max-w-7xl mx-auto px-6">
                    <div className="text-center mb-14">
                        <p className="text-blue-600 font-semibold uppercase tracking-[0.2em] text-[11px] mb-3 font-mono">What We Do</p>
                        <h2 className="text-3xl lg:text-4xl font-bold text-slate-900">
                            Multi-Layer Defense Architecture
                        </h2>
                        <p className="text-slate-500 mt-4 max-w-2xl mx-auto">
                            From kernel-level packet blocking to AI anomaly detection and kill chain tracking —
                            every layer of your network is protected.
                        </p>
                    </div>

                    <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-6">
                        {FEATURES.map((f) => (
                            <div
                                key={f.title}
                                className="group bg-white rounded-2xl p-6 shadow-sm border border-slate-100 hover:shadow-md hover:border-blue-200 hover:-translate-y-1 transition-all duration-200"
                            >
                                <div className="text-3xl mb-4">{f.icon}</div>
                                <h3 className="text-base font-bold text-slate-900 mb-2 group-hover:text-blue-600 transition-colors">
                                    {f.title}
                                </h3>
                                <p className="text-sm text-slate-500 leading-relaxed">{f.desc}</p>
                            </div>
                        ))}
                    </div>
                </div>
            </section>

            {/* ── Terminal Preview ── */}
            <section id="console" className="py-20 bg-white">
                <div className="max-w-7xl mx-auto px-6">
                    <div className="text-center mb-12">
                        <p className="text-blue-600 font-semibold uppercase tracking-[0.2em] text-[11px] mb-3 font-mono">Live Console</p>
                        <h2 className="text-3xl lg:text-4xl font-bold text-slate-900">
                            Defense System in Action
                        </h2>
                        <p className="text-slate-500 mt-3 max-w-xl mx-auto">
                            Watch the system intercept and block threats in real time.
                        </p>
                    </div>

                    <div className="max-w-3xl mx-auto rounded-2xl overflow-hidden border border-slate-200 shadow-xl">
                        {/* Window chrome */}
                        <div className="flex items-center gap-2 px-4 py-3 bg-slate-100 border-b border-slate-200">
                            <div className="w-3 h-3 rounded-full bg-red-400" />
                            <div className="w-3 h-3 rounded-full bg-yellow-400" />
                            <div className="w-3 h-3 rounded-full bg-green-400" />
                            <span className="ml-4 text-xs font-mono text-slate-400 uppercase tracking-widest">
                                WiFi Shield — Defense Engine
                            </span>
                        </div>
                        {/* Log output */}
                        <div
                            ref={terminalRef}
                            className="bg-slate-900 p-6 h-60 overflow-y-auto font-mono text-sm space-y-2"
                        >
                            {LOG_LINES.slice(0, visibleLines).map((line, i) => (
                                <div key={i} className={`${line.color} transition-opacity duration-500`}>
                                    <span className="text-slate-600 mr-2 select-none">{String(i + 1).padStart(2, '0')}</span>
                                    {line.text}
                                    {i === visibleLines - 1 && (
                                        <span className="inline-block w-2 h-4 ml-1 bg-blue-400 animate-pulse align-middle" />
                                    )}
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            </section>

            {/* ── CTA Banner ── */}
            <section className="bg-blue-600 py-16">
                <div className="max-w-3xl mx-auto px-6 text-center text-white">
                    <h2 className="text-3xl font-bold mb-4">Ready to Secure Your Network?</h2>
                    <p className="text-blue-100 mb-8">
                        Join thousands of institutions already protected by WiFi Shield.
                    </p>
                    <div className="flex flex-wrap justify-center gap-4">
                        <Link
                            to="/register"
                            className="px-8 py-3.5 bg-white text-blue-600 font-bold rounded-2xl shadow-lg hover:shadow-xl hover:scale-105 transition-all"
                        >
                            Get Started Free →
                        </Link>
                        <Link
                            to="/login"
                            className="px-8 py-3.5 border-2 border-white/50 text-white font-bold rounded-2xl hover:bg-white/10 hover:scale-105 transition-all"
                        >
                            Sign In
                        </Link>
                    </div>
                </div>
            </section>

            {/* ── Footer ── */}
            <footer className="bg-slate-900 text-slate-400">
                <div className="max-w-7xl mx-auto px-6 py-8 flex flex-col sm:flex-row items-center justify-between gap-4 text-[11px] uppercase tracking-[0.2em] font-mono">
                    <div className="flex items-center gap-2 text-slate-500">
                        <ShieldWifiIcon className="w-4 h-4 text-blue-500" />
                        <span>WiFi Shield — All Rights Reserved</span>
                    </div>
                    <div className="flex items-center gap-6 text-slate-500">
                        <Link to="/login" className="hover:text-white transition-colors">Login</Link>
                        <Link to="/register" className="hover:text-white transition-colors">Register</Link>
                    </div>
                </div>
            </footer>
        </div>
    );
};

export default LandingPage;
