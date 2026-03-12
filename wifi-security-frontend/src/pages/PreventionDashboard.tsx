import React, { useState, useEffect, useCallback } from 'react';
import {
    ShieldCheckIcon,
    BoltIcon,
    CpuChipIcon,
    ServerStackIcon,
    ClockIcon,
    CheckCircleIcon,
    ArrowTrendingDownIcon,
    SignalIcon,
    XCircleIcon,
    ArrowDownTrayIcon,
    EyeIcon,
    BeakerIcon,
    WifiIcon,
    GlobeAltIcon,
    SparklesIcon,
    ExclamationTriangleIcon,
    DocumentTextIcon,
} from '@heroicons/react/24/outline';
import { AppNavbar } from '../components/layout/AppNavbar';

const PREVENTION_API = 'http://localhost:5002';

/* ─── types ─── */
interface PreventionEvent {
    id: string;
    detection_event_id: string;
    created_at: string;
    attacker_mac: string;
    victim_mac: string;
    confidence: number;
    baseline_latency_ms: number | null;
    optimized_latency_ms: number | null;
    improvement_pct: number | null;
    level1_fired: boolean;
    level2_fired: boolean;
    level3_fired: boolean;
    components_fired: string;
    honeypot_active: boolean;
    forensic_report_path: string | null;
    status: 'pending' | 'applied' | 'measured' | 'error';
    error_msg: string | null;
}

interface Stats {
    total: number;
    avg_baseline_ms: number;
    avg_optimized_ms: number;
    avg_improvement_pct: number;
    best_ms: number;
    events_today: number;
    l1_count: number;
    l2_count: number;
    l3_count: number;

}

interface HoneypotStatus {
    active: boolean;
    fake_aps: number;
    fake_clients: number;
    total_visible_networks: number;
    attack_probability_pct: number;
    both_probability_pct: number;
}

/* ─── component definitions ─── */
const DEFENSE_LEVELS = [
    {
        level: 1,
        title: 'Fast Reconnection',
        threshold: '',
        color: 'blue',
        components: [
            { id: '1A', name: 'Pre-Association Caching (OKC)', icon: ShieldCheckIcon },
            { id: '1B', name: 'Aggressive Probe Response', icon: BoltIcon },
            { id: '1C', name: 'Channel Hint Broadcasting', icon: SignalIcon },
            { id: '1D', name: 'Predictive Pre-Authentication', icon: SparklesIcon },
        ],
    },
    {
        level: 2,
        title: 'Application Resilience',
        threshold: '≥60%',
        color: 'emerald',
        components: [
            { id: '2A', name: 'TCP Connection Preservation', icon: ServerStackIcon },
            { id: '2B', name: 'Session Persistence (MPTCP)', icon: GlobeAltIcon },
            { id: '2C', name: 'Smart Buffering', icon: CpuChipIcon },
            { id: '2D', name: 'Intelligent Download Manager', icon: ArrowDownTrayIcon },
        ],
    },
    {
        level: 3,
        title: 'UX Optimization',
        threshold: '≥85%',
        color: 'purple',
        components: [
            { id: '3A', name: 'Perceptual Masking', icon: EyeIcon },
            { id: '3B', name: 'Notification Suppression', icon: XCircleIcon },
            { id: '3C', name: 'Seamless Handoff Illusion', icon: WifiIcon },
            { id: '3D', name: 'Progressive Degradation', icon: ArrowTrendingDownIcon },
        ],
    },
];

/* ─── helpers ─── */
const fmt = (ms: number | string | null): string =>
    ms !== null && ms !== undefined ? `${Number(ms).toFixed(1)}ms` : '—';

const fmtTime = (iso: string): string => {
    try {
        const d = new Date(iso);
        return d.toLocaleTimeString('en-IN', { hour12: false });
    } catch {
        return iso;
    }
};

const fmtPercent = (pct: number | string | null): string =>
    pct !== null && pct !== undefined ? `${Number(pct).toFixed(1)}%` : '—';

const levelColorMap: Record<string, { bg: string; iconBg: string; text: string; border: string; badgeBg: string; badgeText: string }> = {
    blue: { bg: 'bg-white', iconBg: 'bg-blue-50', text: 'text-blue-600', border: 'border-gray-100', badgeBg: 'bg-blue-100', badgeText: 'text-blue-800' },
    emerald: { bg: 'bg-white', iconBg: 'bg-emerald-50', text: 'text-emerald-600', border: 'border-gray-100', badgeBg: 'bg-emerald-100', badgeText: 'text-emerald-800' },
    purple: { bg: 'bg-white', iconBg: 'bg-purple-50', text: 'text-purple-600', border: 'border-gray-100', badgeBg: 'bg-purple-100', badgeText: 'text-purple-800' },
    red: { bg: 'bg-white', iconBg: 'bg-red-50', text: 'text-red-600', border: 'border-gray-100', badgeBg: 'bg-red-100', badgeText: 'text-red-800' },
};

/* ─── main component ─── */
const PreventionDashboard: React.FC = () => {
    const [events, setEvents] = useState<PreventionEvent[]>([]);
    const [stats, setStats] = useState<Stats | null>(null);
    const [honeypotStatus, setHoneypotStatus] = useState<HoneypotStatus | null>(null);
    const [engineOnline, setEngineOnline] = useState(false);
    const [honeypotLoading, setHoneypotLoading] = useState(false);
    const [firedComponents, setFiredComponents] = useState<Set<string>>(new Set());
    const [showForensics, setShowForensics] = useState(false);
    const [forensicTab, setForensicTab] = useState<'pdf' | 'pcap'>('pdf');
    const [forensicReports, setForensicReports] = useState<{ reports: any[], pcaps: any[] }>({ reports: [], pcaps: [] });

    /* ── fetch data ── */
    const fetchData = useCallback(async () => {
        try {
            const [evRes, stRes, hpRes] = await Promise.all([
                fetch(`${PREVENTION_API}/prevention/events?limit=50`).catch(() => null),
                fetch(`${PREVENTION_API}/prevention/stats`).catch(() => null),
                fetch(`${PREVENTION_API}/honeypot/status`).catch(() => null),
            ]);

            if (evRes?.ok) {
                const data = await evRes.json();
                setEvents(data);
                const fired = new Set<string>();
                data.forEach((ev: PreventionEvent) => {
                    if (ev.components_fired) {
                        ev.components_fired.split(',').forEach(c => fired.add(c.trim()));
                    }
                    if (ev.level1_fired) ['1A', '1B', '1C', '1D'].forEach(c => fired.add(c));
                    if (ev.level2_fired) ['2A', '2B', '2C', '2D'].forEach(c => fired.add(c));
                    if (ev.level3_fired) ['3A', '3B', '3C', '3D'].forEach(c => fired.add(c));
                });
                setFiredComponents(fired);
            }

            if (stRes?.ok) setStats(await stRes.json());
            if (hpRes?.ok) setHoneypotStatus(await hpRes.json());

            setEngineOnline(evRes?.ok || stRes?.ok || false);
        } catch {
            setEngineOnline(false);
        }
    }, []);

    useEffect(() => {
        fetchData();
        const iv = setInterval(fetchData, 5000);
        return () => clearInterval(iv);
    }, [fetchData]);

    /* ── honeypot toggle ── */
    const toggleHoneypot = async () => {
        setHoneypotLoading(true);
        try {
            const action = honeypotStatus?.active ? 'stop' : 'start';
            const res = await fetch(`${PREVENTION_API}/honeypot/${action}`, { method: 'POST' });
            if (res.ok) {
                const data = await res.json();
                if (data.status) setHoneypotStatus(data.status);
            } else {
                console.error('Honeypot toggle returned', res.status);
            }
            // Refresh all data after a short delay
            setTimeout(fetchData, 500);
        } catch (e) {
            console.error('Honeypot toggle failed:', e);
        }
        setHoneypotLoading(false);
    };

    /* ── clear events ── */
    const clearEvents = async () => {
        try {
            await fetch(`${PREVENTION_API}/prevention/events`, { method: 'DELETE' });
            setEvents([]);
            setFiredComponents(new Set());
            setForensicReports({ reports: [], pcaps: [] });
            setStats({
                total: 0,
                avg_baseline_ms: 0,
                avg_optimized_ms: 0,
                avg_improvement_pct: 0,
                best_ms: 0,
                events_today: 0,
                l1_count: 0,
                l2_count: 0,
                l3_count: 0
            });
            fetchData();
        } catch (e) {
            console.error('Clear failed:', e);
        }
    };

    /* ── get fired level label ── */
    const getLevelLabel = (ev: PreventionEvent): string => {
        const parts = [];
        if (ev.level1_fired) parts.push('L1');
        if (ev.level2_fired) parts.push('L2');
        if (ev.level3_fired) parts.push('L3');
        return parts.join('+') || 'L1';
    };

    return (
        <div className="min-h-screen bg-gray-50">
            <AppNavbar />

            <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
                {/* ── Header ── */}
                <div className="flex items-center justify-between mb-8">
                    <div>
                        <h1 className="text-3xl font-bold text-gray-900">Prevention Dashboard</h1>
                        <p className="mt-1 text-gray-500">3-Level Defense • Honeypot • Forensics</p>
                    </div>
                    <div className="flex items-center gap-3">
                        <span className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-semibold ${engineOnline
                            ? 'bg-green-100 text-green-800'
                            : 'bg-red-100 text-red-800'
                            }`}>
                            <span className={`w-2 h-2 rounded-full ${engineOnline ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`} />
                            {engineOnline ? 'Engine Online' : 'Engine Offline'}
                        </span>
                        <button
                            onClick={clearEvents}
                            className="text-sm font-medium px-3 py-1.5 border border-gray-200 rounded-lg text-gray-500 hover:text-red-600 hover:border-red-200 hover:bg-red-50 transition-colors"
                        >
                            Clear History
                        </button>
                    </div>
                </div>

                {/* ── KPI Cards ── */}
                <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-4 mb-10">
                    {[
                        {
                            label: 'Avg Baseline',
                            value: fmt(stats?.avg_baseline_ms ?? null),
                            sub: 'Before defense',
                            iconColor: 'text-red-600',
                            iconBg: 'bg-red-50',
                            icon: ClockIcon,
                        },
                        {
                            label: 'Avg Optimized',
                            value: fmt(stats?.avg_optimized_ms ?? null),
                            sub: 'After defense',
                            iconColor: 'text-emerald-600',
                            iconBg: 'bg-emerald-50',
                            icon: BoltIcon,
                        },
                        {
                            label: 'Improvement',
                            value: fmtPercent(stats?.avg_improvement_pct ?? null),
                            sub: 'Latency reduction',
                            iconColor: 'text-blue-600',
                            iconBg: 'bg-blue-50',
                            icon: ArrowTrendingDownIcon,
                        },
                        {
                            label: 'Events Today',
                            value: String(stats?.events_today ?? 0),
                            sub: `${stats?.total ?? 0} total`,
                            iconColor: 'text-purple-600',
                            iconBg: 'bg-purple-50',
                            icon: ShieldCheckIcon,
                        },
                    ].map((kpi) => (
                        <div
                            key={kpi.label}
                            className="rounded-xl bg-white p-6 shadow-sm border border-gray-100 flex items-center justify-between"
                        >
                            <div>
                                <p className="text-[11px] font-semibold text-gray-500 font-mono uppercase tracking-[0.2em]">
                                    {kpi.label}
                                </p>
                                <p className="mt-2 text-3xl font-bold text-gray-900">{kpi.value}</p>
                                <p className="mt-1 text-sm text-gray-400">{kpi.sub}</p>
                            </div>
                            <div className={`flex h-10 w-10 items-center justify-center rounded-lg ${kpi.iconBg}`}>
                                <kpi.icon className={`h-5 w-5 ${kpi.iconColor}`} />
                            </div>
                        </div>
                    ))}
                </div>

                {/* ── Honeypot Control ── */}
                <div className="rounded-xl bg-white p-6 shadow-sm border border-gray-100 mb-8">
                    <div className="flex items-center justify-between">
                        <div>
                            <div className="flex items-center gap-3 mb-2">
                                <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-amber-50">
                                    <BeakerIcon className="h-4 w-4 text-amber-600" />
                                </div>
                                <h2 className="text-lg font-bold text-gray-900">
                                    Honeypot Deception System
                                </h2>
                            </div>
                            <div className="flex flex-wrap items-center gap-4 ml-11">
                                <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold ${honeypotStatus?.active
                                    ? 'bg-green-100 text-green-800'
                                    : 'bg-red-100 text-red-800'
                                    }`}>
                                    <span className={`w-1.5 h-1.5 rounded-full ${honeypotStatus?.active ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`} />
                                    {honeypotStatus?.active ? 'Active' : 'Inactive'}
                                </span>
                                {honeypotStatus?.active && (
                                    <>
                                        <span className="text-sm text-gray-500">
                                            Fake APs: <span className="font-semibold text-amber-600">{honeypotStatus.fake_aps}</span>
                                        </span>
                                        <span className="text-sm text-gray-500">
                                            Fake Clients: <span className="font-semibold text-amber-600">{honeypotStatus.fake_clients}</span>
                                        </span>
                                        <span className="text-sm text-gray-500">
                                            Attack Prob: <span className="font-semibold text-green-600">{Number(honeypotStatus.both_probability_pct ?? 0).toFixed(4)}%</span>
                                        </span>
                                    </>
                                )}
                            </div>
                        </div>
                        <button
                            onClick={toggleHoneypot}
                            disabled={honeypotLoading}
                            className={`px-5 py-2.5 rounded-lg text-sm font-semibold transition-all ${honeypotStatus?.active
                                ? 'bg-red-50 border border-red-200 text-red-700 hover:bg-red-100'
                                : 'bg-emerald-50 border border-emerald-200 text-emerald-700 hover:bg-emerald-100'
                                } ${honeypotLoading ? 'opacity-50 cursor-not-allowed' : ''}`}
                        >
                            {honeypotLoading ? '...' : honeypotStatus?.active ? 'Deactivate' : 'Activate'}
                        </button>
                    </div>
                </div>

                {/* ── Defense Levels Grid ── */}
                <div className="mb-8">
                    <h3 className="text-xl font-bold text-gray-900 mb-6">Defense Levels</h3>
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                        {DEFENSE_LEVELS.map((level) => {
                            const colors = levelColorMap[level.color];
                            const levelFired = events.some(ev => {
                                const key = `level${level.level}_fired` as keyof PreventionEvent;
                                return ev[key];
                            });

                            return (
                                <div
                                    key={level.level}
                                    className={`rounded-xl ${colors.bg} p-6 shadow-sm border ${colors.border}`}
                                >
                                    <div className="flex items-center justify-between mb-4">
                                        <div className="flex items-center gap-3">
                                            <div className={`flex h-10 w-10 items-center justify-center rounded-lg ${colors.iconBg}`}>
                                                <span className={`text-sm font-bold ${colors.text}`}>L{level.level}</span>
                                            </div>
                                            <div>
                                                <h4 className="font-bold text-gray-900">{level.title}</h4>
                                                <p className="text-xs text-gray-400">{level.threshold ? `${level.threshold} confidence` : 'Base defense'}</p>
                                            </div>
                                        </div>
                                        {levelFired && (
                                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold ${colors.badgeBg} ${colors.badgeText}`}>
                                                Fired
                                            </span>
                                        )}
                                    </div>
                                    <div className="space-y-2">
                                        {level.components.map((comp) => {
                                            const fired = firedComponents.has(comp.id);
                                            const Icon = comp.icon;
                                            return (
                                                <div
                                                    key={comp.id}
                                                    className={`flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all ${fired
                                                        ? 'bg-gray-50 border border-gray-200'
                                                        : 'bg-transparent'
                                                        }`}
                                                >
                                                    {fired ? (
                                                        <CheckCircleIcon className="h-4 w-4 text-green-500 flex-shrink-0" />
                                                    ) : (
                                                        <div className="h-4 w-4 rounded-full border-2 border-gray-200 flex-shrink-0" />
                                                    )}
                                                    <Icon className={`h-4 w-4 flex-shrink-0 ${fired ? 'text-gray-600' : 'text-gray-300'}`} />
                                                    <span className={`text-sm ${fired ? 'text-gray-800 font-medium' : 'text-gray-400'}`}>
                                                        {comp.name}
                                                    </span>
                                                    <span className={`ml-auto text-xs font-mono ${fired ? 'text-gray-500' : 'text-gray-300'}`}>
                                                        {comp.id}
                                                    </span>
                                                </div>
                                            );
                                        })}
                                    </div>
                                </div>
                            );
                        })}
                    </div>
                </div>

                {/* ── Live Events Feed ── */}
                <div className="mb-8">
                    <div className="flex items-center justify-between mb-6">
                        <h3 className="text-xl font-bold text-gray-900">Recent Prevention Events</h3>
                        <span className="text-xs text-gray-400 font-mono uppercase tracking-wider">Auto-refresh 5s</span>
                    </div>

                    <div className="rounded-xl border border-gray-200 bg-white overflow-hidden shadow-sm">
                        {events.length === 0 ? (
                            <div className="px-6 py-12 text-center">
                                <ShieldCheckIcon className="mx-auto h-12 w-12 text-gray-200" />
                                <h3 className="mt-4 text-lg font-semibold text-gray-900">No prevention events yet</h3>
                                <p className="mt-2 text-sm text-gray-500 max-w-md mx-auto">
                                    Events will appear when attacks are detected and defenses fire
                                </p>
                            </div>
                        ) : (
                            <div className="overflow-x-auto">
                                <table className="min-w-full divide-y divide-gray-200">
                                    <thead className="bg-gray-50">
                                        <tr>
                                            <th className="px-6 py-3 text-left text-[11px] font-semibold text-gray-500 font-mono uppercase tracking-[0.2em]">Time</th>
                                            <th className="px-6 py-3 text-left text-[11px] font-semibold text-gray-500 font-mono uppercase tracking-[0.2em]">Confidence</th>
                                            <th className="px-6 py-3 text-left text-[11px] font-semibold text-gray-500 font-mono uppercase tracking-[0.2em]">Levels</th>
                                            <th className="px-6 py-3 text-left text-[11px] font-semibold text-gray-500 font-mono uppercase tracking-[0.2em]">Attacker</th>
                                            <th className="px-6 py-3 text-left text-[11px] font-semibold text-gray-500 font-mono uppercase tracking-[0.2em]">Latency</th>
                                            <th className="px-6 py-3 text-left text-[11px] font-semibold text-gray-500 font-mono uppercase tracking-[0.2em]">Status</th>
                                        </tr>
                                    </thead>
                                    <tbody className="bg-white divide-y divide-gray-100">
                                        {events.slice(0, 20).map((ev) => (
                                            <tr key={ev.id} className="hover:bg-gray-50 transition-colors">
                                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 font-mono">
                                                    {fmtTime(ev.created_at)}
                                                </td>
                                                <td className="px-6 py-4 whitespace-nowrap">
                                                    <span className={`text-sm font-semibold ${Number(ev.confidence) >= 85 ? 'text-red-600' :
                                                        Number(ev.confidence) >= 60 ? 'text-orange-600' :
                                                            'text-blue-600'
                                                        }`}>
                                                        {Number(ev.confidence).toFixed(1)}%
                                                    </span>
                                                </td>
                                                <td className="px-6 py-4 whitespace-nowrap">
                                                    <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-700">
                                                        {getLevelLabel(ev)}
                                                    </span>
                                                    {ev.honeypot_active && (
                                                        <span className="ml-1 inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-amber-100 text-amber-700">
                                                            🍯
                                                        </span>
                                                    )}
                                                </td>
                                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 font-mono">
                                                    {ev.attacker_mac}
                                                </td>
                                                <td className="px-6 py-4 whitespace-nowrap text-sm">
                                                    {ev.improvement_pct !== null ? (
                                                        <span className="text-green-600 font-medium">
                                                            {fmt(ev.baseline_latency_ms)} → {fmt(ev.optimized_latency_ms)}
                                                            <span className="ml-1 text-xs">↓{Number(ev.improvement_pct).toFixed(1)}%</span>
                                                        </span>
                                                    ) : (
                                                        <span className="text-gray-400">—</span>
                                                    )}
                                                </td>
                                                <td className="px-6 py-4 whitespace-nowrap">
                                                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold ${ev.status === 'measured' ? 'bg-green-100 text-green-800' :
                                                        ev.status === 'applied' ? 'bg-blue-100 text-blue-800' :
                                                            ev.status === 'error' ? 'bg-red-100 text-red-800' :
                                                                'bg-yellow-100 text-yellow-800'
                                                        }`}>
                                                        {ev.status}
                                                    </span>
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        )}
                    </div>
                </div>

                {/* ── Forensic Reports & PCAP Captures Section ── */}
                <div className="bg-white rounded-2xl border border-gray-100 shadow-sm overflow-hidden">
                    <button
                        onClick={async () => {
                            setShowForensics(prev => !prev);
                            if (!showForensics) {
                                try {
                                    const res = await fetch(`${PREVENTION_API}/forensics/reports`);
                                    if (res.ok) setForensicReports(await res.json());
                                } catch { /* engine offline */ }
                            }
                        }}
                        className="w-full flex items-center justify-between px-6 py-4 hover:bg-gray-50 transition-colors"
                    >
                        <div className="flex items-center gap-3">
                            <DocumentTextIcon className="h-5 w-5 text-blue-500" />
                            <span className="text-sm font-semibold text-gray-900">Forensic Reports & PCAP Captures</span>
                            <span className="inline-flex items-center gap-1.5 text-xs text-gray-400">
                                <span className="px-1.5 py-0.5 rounded bg-red-50 text-red-600 font-bold">{forensicReports.reports.length} PDF</span>
                                <span>+</span>
                                <span className="px-1.5 py-0.5 rounded bg-blue-50 text-blue-600 font-bold">{forensicReports.pcaps.length} PCAP</span>
                            </span>
                        </div>
                        <span className="text-gray-400 text-sm">{showForensics ? '▲ Hide' : '▼ Show'}</span>
                    </button>

                    {showForensics && (
                        <div className="border-t border-gray-50">
                            {forensicReports.reports.length === 0 && forensicReports.pcaps.length === 0 ? (
                                <p className="text-sm text-gray-400 py-8 text-center">No forensic reports yet. Reports are generated during attack events.</p>
                            ) : (
                                <>
                                    {/* Tabs */}
                                    <div className="flex border-b border-gray-100">
                                        <button
                                            onClick={() => setForensicTab('pdf')}
                                            className={`flex-1 py-3 text-sm font-semibold text-center transition-colors relative ${forensicTab === 'pdf'
                                                ? 'text-red-600 bg-red-50/50'
                                                : 'text-gray-400 hover:text-gray-600 hover:bg-gray-50'
                                                }`}
                                        >
                                            <span className="flex items-center justify-center gap-2">
                                                <DocumentTextIcon className="h-4 w-4" />
                                                PDF Reports
                                                <span className={`px-2 py-0.5 rounded-full text-xs font-bold ${forensicTab === 'pdf' ? 'bg-red-100 text-red-700' : 'bg-gray-100 text-gray-500'}`}>
                                                    {forensicReports.reports.length}
                                                </span>
                                            </span>
                                            {forensicTab === 'pdf' && <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-red-500" />}
                                        </button>
                                        <button
                                            onClick={() => setForensicTab('pcap')}
                                            className={`flex-1 py-3 text-sm font-semibold text-center transition-colors relative ${forensicTab === 'pcap'
                                                ? 'text-blue-600 bg-blue-50/50'
                                                : 'text-gray-400 hover:text-gray-600 hover:bg-gray-50'
                                                }`}
                                        >
                                            <span className="flex items-center justify-center gap-2">
                                                <ServerStackIcon className="h-4 w-4" />
                                                PCAP Captures
                                                <span className={`px-2 py-0.5 rounded-full text-xs font-bold ${forensicTab === 'pcap' ? 'bg-blue-100 text-blue-700' : 'bg-gray-100 text-gray-500'}`}>
                                                    {forensicReports.pcaps.length}
                                                </span>
                                            </span>
                                            {forensicTab === 'pcap' && <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-blue-500" />}
                                        </button>
                                    </div>

                                    {/* File List */}
                                    <div className="px-6 pb-5">
                                        <div className="space-y-2 mt-4 max-h-[480px] overflow-y-auto">
                                            {(forensicTab === 'pdf' ? forensicReports.reports : forensicReports.pcaps).map((file, i) => (
                                                <div key={i} className="flex items-center justify-between py-2.5 px-4 rounded-lg bg-gray-50 hover:bg-gray-100 transition-colors group">
                                                    <div className="flex items-center gap-3 min-w-0">
                                                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider flex-shrink-0 ${file.type === 'pdf'
                                                            ? 'bg-red-100 text-red-700'
                                                            : 'bg-blue-100 text-blue-700'
                                                            }`}>{file.type}</span>
                                                        <span className="text-sm font-medium text-gray-800 truncate">{file.filename}</span>
                                                        <span className="text-xs text-gray-400 flex-shrink-0">{(file.size / 1024).toFixed(1)} KB</span>
                                                    </div>
                                                    <a
                                                        href={`${PREVENTION_API}/forensics/download/${file.filename}`}
                                                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-50 text-blue-600 text-xs font-semibold hover:bg-blue-100 transition-colors flex-shrink-0 ml-3"
                                                        download
                                                    >
                                                        <ArrowDownTrayIcon className="h-3.5 w-3.5" />
                                                        Download
                                                    </a>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                </>
                            )}
                        </div>
                    )}
                </div>
            </main>
        </div>
    );
};

export { PreventionDashboard };
