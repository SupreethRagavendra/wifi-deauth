import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';

// ── WiFi Shield SVG Icon ──
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

// ── Status Badge ──
const StatusBadge: React.FC<{ color: string; label: string; value: string }> = ({ color, label, value }) => (
    <div className="inline-flex items-center gap-2.5 px-4 py-2 rounded-full border border-slate-200 bg-white/90 shadow-sm font-mono">
        <span className={`w-2.5 h-2.5 rounded-full ${color}`} />
        <span className="text-[11px] font-bold text-slate-800 uppercase tracking-[0.15em]">{label}</span>
        <span className="text-[11px] text-slate-400 font-medium tracking-[0.1em]">{value}</span>
    </div>
);

// ── Floating Dot ──
const FloatingDot: React.FC<{
    size: number; top: string; left: string; delay: string; duration: string; opacity?: number;
}> = ({ size, top, left, delay, duration, opacity = 0.6 }) => (
    <div
        className="absolute rounded-full bg-blue-500"
        style={{ width: size, height: size, top, left, opacity, animation: `floatDot ${duration} ${delay} ease-in-out infinite` }}
    />
);

// ── Live status ──
function useLiveStatus() {
    const [status, setStatus] = useState({
        widsEngine: 'Scapy', mlModels: '4 Model', prevention: 'Level 1-3', targeting: 'Deception',
    });
    useEffect(() => {
        const fetchStatus = async () => {
            try {
                const res = await fetch('http://localhost:5001/stats');
                if (res.ok) {
                    const data = await res.json();
                    setStatus(s => ({
                        ...s,
                        widsEngine: data.current_status === 'SAFE' ? 'Scapy' : 'Active',
                        mlModels: `${data.ml_models_loaded} Model`,
                    }));
                }
            } catch { /* defaults */ }
        };
        fetchStatus();
        const interval = setInterval(fetchStatus, 10000);
        return () => clearInterval(interval);
    }, []);
    return status;
}

// ── Animations ──
const AnimationStyles: React.FC = () => (
    <style>{`
        @keyframes floatDot {
            0%, 100% { transform: translateY(0) scale(1); opacity: 0.5; }
            50% { transform: translateY(-18px) scale(1.15); opacity: 0.8; }
        }
        @keyframes orbitSpin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        @keyframes pulseGlow {
            0%, 100% { box-shadow: 0 0 30px rgba(59,130,246,0.15); }
            50% { box-shadow: 0 0 60px rgba(59,130,246,0.3); }
        }
        @keyframes fadeInUp {
            0% { opacity: 0; transform: translateY(30px); }
            100% { opacity: 1; transform: translateY(0); }
        }
        .anim-up { animation: fadeInUp 0.8s ease-out forwards; }
        .anim-up-1 { animation: fadeInUp 0.8s 0.15s ease-out forwards; opacity: 0; }
        .anim-up-2 { animation: fadeInUp 0.8s 0.3s ease-out forwards; opacity: 0; }
        .anim-up-3 { animation: fadeInUp 0.8s 0.45s ease-out forwards; opacity: 0; }
        .anim-up-4 { animation: fadeInUp 0.8s 0.6s ease-out forwards; opacity: 0; }
    `}</style>
);

// ── Main Component ──
export const LandingPage: React.FC = () => {
    const status = useLiveStatus();

    return (
        <div
            className="h-screen w-screen overflow-hidden bg-white text-slate-900 flex flex-col"
            style={{ fontFamily: "'Inter', sans-serif" }}
        >
            <AnimationStyles />

            {/* ── Navbar ── */}
            <header className="flex-shrink-0 bg-white/90 backdrop-blur border-b border-slate-100 shadow-sm z-50">
                <nav className="max-w-[1500px] mx-auto px-8 lg:px-16 h-14 flex items-center justify-between">
                    <div className="flex items-center gap-2.5">
                        <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-blue-600 shadow-md">
                            <ShieldWifiIcon className="w-5 h-5 text-white" />
                        </div>
                        <span className="text-lg font-bold tracking-[0.15em] text-blue-700 uppercase font-mono">
                            WiFi Shield
                        </span>
                    </div>
                    <div className="flex items-center gap-3">
                        <Link to="/login" className="px-4 py-2 text-sm font-semibold text-blue-600 border border-blue-200 rounded-xl hover:bg-blue-50 transition-all">
                            Sign In
                        </Link>
                        <Link to="/register" className="px-4 py-2 text-sm font-semibold bg-blue-600 hover:bg-blue-700 text-white rounded-xl shadow-md hover:shadow-lg transition-all">
                            Get Started
                        </Link>
                    </div>
                </nav>
            </header>

            {/* ── Hero — fills remaining viewport ── */}
            <main className="flex-1 flex items-center overflow-hidden">
                <div className="max-w-[1500px] mx-auto px-8 lg:px-16 w-full grid lg:grid-cols-2 gap-12 items-center">

                    {/* Left — Copy */}
                    <div>
                        <div className="text-[13px] font-semibold uppercase tracking-[0.2em] font-mono text-blue-600 mb-5 anim-up">
                            Scapy WIDS &nbsp;·&nbsp; Ensemble ML &nbsp;·&nbsp; Active Deception
                        </div>

                        <h1 className="text-7xl lg:text-8xl font-extrabold leading-[1.05] mb-5 text-slate-900 tracking-tight anim-up-1">
                            WiFi{' '}<span className="text-blue-600">Security</span><br />Made Simple.
                        </h1>

                        <p className="text-xl text-slate-400 leading-relaxed mb-7 max-w-xl anim-up-2">
                            Machine learning-powered protection against
                            deauthentication attacks. Features active
                            deception, TCP connection preservation, and a
                            real-time dashboard.
                        </p>

                        <div className="flex flex-wrap gap-4 mb-6 anim-up-3">
                            <Link to="/register" className="inline-flex items-center gap-2 px-8 py-4 text-base bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-2xl shadow-lg hover:shadow-xl transition-all hover:scale-105 active:scale-95">
                                Get Started Free
                                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M14 5l7 7m0 0l-7 7m7-7H3" />
                                </svg>
                            </Link>
                            <Link to="/login" className="inline-flex items-center gap-2 px-8 py-4 text-base border-2 border-slate-200 text-slate-600 hover:border-blue-300 hover:text-blue-600 font-semibold rounded-2xl transition-all hover:scale-105 active:scale-95">
                                Sign In
                            </Link>
                        </div>

                        {/* Status Badges */}
                        <div className="flex flex-wrap gap-2 anim-up-4">
                            <StatusBadge color="bg-green-500" label="WIDS Engine" value={status.widsEngine} />
                            <StatusBadge color="bg-green-500" label="ML Ensemble" value={status.mlModels} />
                            <StatusBadge color="bg-red-500" label="Prevention" value={status.prevention} />
                            <StatusBadge color="bg-amber-500" label="Targeting" value={status.targeting} />
                        </div>
                    </div>

                    {/* Right — Hero image with animations */}
                    <div className="relative flex items-center justify-center h-full">
                        {/* Glow blob */}
                        <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
                            <div className="w-[600px] h-[600px] rounded-full bg-blue-100/70 blur-3xl" style={{ animation: 'pulseGlow 4s ease-in-out infinite' }} />
                        </div>

                        {/* Dotted orbit circles */}
                        <div className="absolute pointer-events-none" style={{ width: 480, height: 480, border: '2px dashed rgba(59,130,246,0.15)', borderRadius: '50%', animation: 'orbitSpin 30s linear infinite' }} />
                        <div className="absolute pointer-events-none" style={{ width: 380, height: 380, border: '1.5px dashed rgba(59,130,246,0.1)', borderRadius: '50%', animation: 'orbitSpin 25s linear infinite reverse' }} />

                        {/* Floating dots */}
                        <FloatingDot size={10} top="8%" left="15%" delay="0s" duration="3s" opacity={0.5} />
                        <FloatingDot size={14} top="3%" left="60%" delay="0.5s" duration="3.5s" opacity={0.6} />
                        <FloatingDot size={8} top="22%" left="88%" delay="1s" duration="2.8s" opacity={0.4} />
                        <FloatingDot size={12} top="60%" left="8%" delay="0.3s" duration="3.2s" opacity={0.5} />
                        <FloatingDot size={6} top="78%" left="80%" delay="0.8s" duration="2.5s" opacity={0.3} />
                        <FloatingDot size={10} top="38%" left="3%" delay="1.2s" duration="3.8s" opacity={0.45} />
                        <FloatingDot size={8} top="12%" left="92%" delay="0.2s" duration="3s" opacity={0.35} />

                        {/* Main hero image */}
                        <img
                            src="/wifi-hero.png"
                            alt="WiFi Security"
                            className="relative z-10 w-full max-w-md drop-shadow-2xl"
                            style={{ animation: 'fadeInUp 1s 0.3s ease-out forwards', opacity: 0 }}
                        />

                        {/* Character with laptop — bottom left */}
                        <img
                            src="/character-laptop.png"
                            alt="Developer"
                            className="absolute bottom-0 left-2 z-20 w-28 lg:w-36 drop-shadow-lg"
                            style={{ animation: 'fadeInUp 0.8s 0.8s ease-out forwards', opacity: 0 }}
                        />

                        {/* Mascot — bottom right */}
                        <img
                            src="/mascot.png"
                            alt="WiFi Shield Mascot"
                            className="absolute bottom-0 right-2 z-20 w-24 lg:w-32 drop-shadow-lg"
                            style={{ animation: 'fadeInUp 0.8s 1s ease-out forwards', opacity: 0 }}
                        />
                    </div>
                </div>
            </main>
        </div>
    );
};

export default LandingPage;
