import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { detectionService, wifiService } from '../services/api';
import { DetectionEvent, WiFiNetwork } from '../types';
import { useDetectionStatus } from '../hooks/useDetectionStatus';
import { useLiveStatus } from '../hooks/useLiveStatus';
import {
    ShieldCheckIcon,
    ShieldExclamationIcon,
    ExclamationTriangleIcon,
    CheckCircleIcon,
    SignalIcon,
    ArrowPathIcon,
    ChevronDownIcon,
    ChevronUpIcon,
} from '@heroicons/react/24/solid';
import { Button } from '../components/ui';
import { MLInsightsCard } from '../components/MLInsightsCard';
import { AppNavbar } from '../components/layout/AppNavbar';

export const DetectionMonitor: React.FC = () => {
    const navigate = useNavigate();
    const { user, logout } = useAuth();
    const { latestAlert } = useDetectionStatus();
    const { threatsLastHour, severityBreakdown } = useLiveStatus();

    const [events, setEvents] = useState<DetectionEvent[]>([]);
    const [networks, setNetworks] = useState<WiFiNetwork[]>([]);
    const [selectedNetwork, setSelectedNetwork] = useState<string>('all');
    const [loading, setLoading] = useState(true);
    const [expandedEvent, setExpandedEvent] = useState<number | null>(null);
    const [threatLevel, setThreatLevel] = useState('SAFE');
    const [activeThreats, setActiveThreats] = useState(0);
    const [underAttack, setUnderAttack] = useState(false);

    const handleLogout = () => {
        logout();
        navigate('/login');
    };

    // Fetch networks on load
    useEffect(() => {
        const fetchNetworks = async () => {
            const response = await wifiService.getNetworks();
            if (response.success && response.data) {
                setNetworks(response.data);
            }
        };
        fetchNetworks();
    }, []);

    // Fetch threat level and recent events
    const fetchData = async () => {
        // Threat level
        const res = await detectionService.getThreatLevel();
        if (res.success && res.data) {
            setThreatLevel(res.data.threatLevel);
            setActiveThreats(res.data.activeThreats);
            setUnderAttack(res.data.underAttack);
        }

        // Recent events (to populate the table when first opening the page)
        try {
            const eventsRes = await fetch(`${process.env.REACT_APP_BACKEND_URL || 'http://localhost:8080'}/api/detection/events/recent`, {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                }
            });
            if (eventsRes.ok) {
                const recentEvents = await eventsRes.json();

                // Map the DB backend events to the frontend Alert interface
                const mappedEvents = recentEvents.map((e: any) => ({
                    eventId: e.eventId,
                    timestamp: new Date(e.detectedAt).getTime().toString(),
                    severity: e.severity,
                    type: e.severity === 'CRITICAL' || e.severity === 'HIGH' ? 'CRITICAL_ALERT' : 'MONITOR_ALERT',
                    attackerMac: e.attackerMac,
                    targetMac: e.targetMac,
                    targetBssid: e.targetBssid,
                    packetCount: e.frameCount || 1,
                    totalScore: e.totalScore || e.layer1Score || 0,
                    layer2Score: e.layer2Score,
                    layer3Score: e.layer3Score,
                    mlConfidence: e.mlConfidence,
                    mlPrediction: e.mlPrediction,
                    isSpoofed: e.isSpoofed,
                    realAttackerMac: e.realAttackerMac,
                    message: e.layer3Notes || `Threat detected from ${e.attackerMac}`
                }));

                setEvents(mappedEvents);
            }
        } catch (err) {
            console.error('Failed to fetch recent events:', err);
        }
        setLoading(false);
    };

    // Initial fetch of events
    useEffect(() => {
        fetchData();
        // Poll threat level every 3 seconds
        const threatInterval = setInterval(fetchData, 3000);
        return () => clearInterval(threatInterval);
    }, []);

    // Sync incoming real-time events
    useEffect(() => {
        if (latestAlert) {
            const newEvent: any = {
                eventId: latestAlert.eventId || Math.floor(Math.random() * 1000000),
                attackerMac: latestAlert.attackerMac,
                targetBssid: latestAlert.targetBssid,
                targetMac: latestAlert.targetMac,
                layer1Score: latestAlert.score || latestAlert.packetCount || 0,
                totalScore: latestAlert.score || 0,
                layer2Score: latestAlert.layer2Score || 0,
                layer3Score: latestAlert.layer3Score || 0,
                mlConfidence: latestAlert.mlConfidence || 0,
                mlPrediction: latestAlert.mlPrediction || 'N/A',
                modelAgreement: latestAlert.modelAgreement || '0/4',
                severity: latestAlert.severity,
                detectedAt: latestAlert.timestamp || new Date().toISOString(),
                attackType: latestAlert.type,
                isSpoofed: latestAlert.isSpoofed,
                realAttackerMac: latestAlert.realAttackerMac,
            };
            setEvents(prev => {
                // Update existing event if same attacker+time, otherwise prepend
                const existingIdx = prev.findIndex(e =>
                    e.attackerMac === newEvent.attackerMac &&
                    Math.abs(new Date(e.detectedAt).getTime() - new Date(newEvent.detectedAt).getTime()) < 2000
                );
                if (existingIdx >= 0) {
                    // Update in place with higher score (ML update)
                    const updated = [...prev];
                    if ((newEvent.totalScore || 0) >= ((updated[existingIdx] as any).totalScore || 0)) {
                        updated[existingIdx] = { ...updated[existingIdx], ...newEvent };
                    }
                    return updated;
                }
                return [newEvent, ...prev].slice(0, 100);
            });
        }
    }, [latestAlert]);

    // P3-2: Network-specific filtering
    const filteredEvents = selectedNetwork === 'all'
        ? events
        : events.filter(e => {
            const network = networks.find(n => String(n.wifiId) === selectedNetwork);
            return network && e.targetBssid?.toUpperCase() === network.bssid?.toUpperCase();
        });
    const isFiltered = selectedNetwork !== 'all';

    // Stats calculations — use server-side severity breakdown (DB-authoritative, time-windowed)
    // Falls back to local array counting when severityBreakdown is empty
    const hasServerStats = severityBreakdown && (severityBreakdown.critical + severityBreakdown.high + severityBreakdown.medium + severityBreakdown.low) > 0;
    const stats = hasServerStats ? {
        total: (severityBreakdown.critical || 0) + (severityBreakdown.high || 0) + (severityBreakdown.medium || 0) + (severityBreakdown.low || 0),
        active: activeThreats,
        normal: severityBreakdown.low || 0,
        suspicious: severityBreakdown.medium || 0,
        attacks: (severityBreakdown.high || 0) + (severityBreakdown.critical || 0),
        critical: severityBreakdown.critical || 0,
    } : {
        total: filteredEvents.length,
        active: activeThreats,
        normal: filteredEvents.filter(e => e.severity === 'LOW').length,
        suspicious: filteredEvents.filter(e => e.severity === 'MEDIUM').length,
        attacks: filteredEvents.filter(e => e.severity === 'HIGH' || e.severity === 'CRITICAL').length,
        critical: filteredEvents.filter(e => e.severity === 'CRITICAL').length,
    };

    const getSeverityColor = (severity: string) => {
        switch (severity) {
            case 'CRITICAL': return 'bg-red-500';
            case 'HIGH': return 'bg-orange-500';
            case 'MEDIUM': return 'bg-yellow-500';
            default: return 'bg-green-500';
        }
    };

    const getSeverityBg = (severity: string) => {
        switch (severity) {
            case 'CRITICAL': return 'bg-red-50 border-red-200';
            case 'HIGH': return 'bg-orange-50 border-orange-200';
            case 'MEDIUM': return 'bg-yellow-50 border-yellow-200';
            default: return 'bg-green-50 border-green-200';
        }
    };

    const getVerdictLabel = (severity: string) => {
        switch (severity) {
            case 'CRITICAL': return 'ATTACK DETECTED';
            case 'HIGH': return 'LIKELY ATTACK';
            case 'MEDIUM': return 'SUSPICIOUS';
            default: return 'NORMAL';
        }
    };

    const getThreatIcon = (severity: string) => {
        if (severity === 'CRITICAL' || severity === 'HIGH') {
            return <ShieldExclamationIcon className="h-5 w-5 text-red-600" />;
        }
        if (severity === 'MEDIUM') {
            return <ExclamationTriangleIcon className="h-5 w-5 text-yellow-600" />;
        }
        return <CheckCircleIcon className="h-5 w-5 text-green-600" />;
    };

    return (
        <div className="min-h-screen bg-gray-50">
            <AppNavbar />

            {/* Main Content */}
            <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
                {/* Title & Network Selector */}
                <div className="mb-8 flex items-center justify-between">
                    <div>
                        <h1 className="text-3xl font-bold text-gray-900">Real-Time Detection Monitor</h1>
                        <p className="mt-1 text-gray-500">Live deauth attack detection feed</p>
                    </div>
                    <div className="flex items-center gap-4">
                        <select
                            value={selectedNetwork}
                            onChange={(e) => setSelectedNetwork(e.target.value)}
                            className="rounded-lg border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 shadow-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                        >
                            <option value="all">All Networks</option>
                            {networks.map(n => (
                                <option key={n.wifiId} value={n.wifiId}>{n.ssid}</option>
                            ))}
                        </select>
                        <div className="flex items-center gap-2 px-3 py-2 bg-green-100 text-green-700 rounded-full text-sm font-medium">
                            <span className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
                            Live
                        </div>
                    </div>
                </div>

                {/* Stats Cards */}
                <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-5 mb-8">
                    <div className="bg-white rounded-xl p-6 shadow-sm border border-gray-100">
                        <div className="flex items-center justify-between">
                            <div>
                                <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-gray-400 font-mono">Active Events</p>
                                <p className="mt-2 text-3xl font-bold text-gray-900">{stats.active}</p>
                            </div>
                            <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-blue-100">
                                <SignalIcon className="h-6 w-6 text-blue-600" />
                            </div>
                        </div>
                    </div>
                    <div className="bg-white rounded-xl p-6 shadow-sm border border-gray-100">
                        <div className="flex items-center justify-between">
                            <div>
                                <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-gray-400 font-mono">
                                    Normal{isFiltered && <span className="ml-1 text-blue-400">(filtered)</span>}
                                </p>
                                <p className="mt-2 text-3xl font-bold text-green-600">{stats.normal}</p>
                            </div>
                            <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-green-100">
                                <CheckCircleIcon className="h-6 w-6 text-green-600" />
                            </div>
                        </div>
                    </div>
                    <div className="bg-white rounded-xl p-6 shadow-sm border border-gray-100">
                        <div className="flex items-center justify-between">
                            <div>
                                <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-gray-400 font-mono">Suspicious</p>
                                <p className="mt-2 text-3xl font-bold text-yellow-600">{stats.suspicious}</p>
                            </div>
                            <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-yellow-100">
                                <ExclamationTriangleIcon className="h-6 w-6 text-yellow-600" />
                            </div>
                        </div>
                    </div>
                    <div className="bg-white rounded-xl p-6 shadow-sm border border-gray-100">
                        <div className="flex items-center justify-between">
                            <div>
                                <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-gray-400 font-mono">Attacks</p>
                                <p className="mt-2 text-3xl font-bold text-orange-500">{stats.attacks}</p>
                            </div>
                            <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-orange-100">
                                <ShieldExclamationIcon className="h-6 w-6 text-orange-500" />
                            </div>
                        </div>
                    </div>
                    <div className="bg-white rounded-xl p-6 shadow-sm border border-red-100">
                        <div className="flex items-center justify-between">
                            <div>
                                <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-red-500 font-mono">Critical Attacks</p>
                                <p className="mt-2 text-3xl font-bold text-red-600">{stats.critical}</p>
                            </div>
                            <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-red-100 animate-pulse">
                                <ShieldExclamationIcon className="h-6 w-6 text-red-600" />
                            </div>
                        </div>
                    </div>
                </div>

                {/* Two-column layout: Detection feed + ML card sidebar */}
                <div className="flex gap-6">
                    {/* Main Detection Feed */}
                    <div className="flex-1 min-w-0">
                        <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
                            <div className="px-6 py-4 border-b border-gray-100 flex justify-between items-center bg-gray-50">
                                <h3 className="text-lg font-semibold text-gray-800">Live Detection Feed</h3>
                                <button
                                    onClick={() => window.location.reload()}
                                    className="flex items-center gap-2 text-sm text-gray-500 hover:text-gray-700"
                                >
                                    <ArrowPathIcon className="h-4 w-4" />
                                    Refresh
                                </button>
                            </div>

                            <div className="divide-y divide-gray-100 max-h-[500px] overflow-y-auto">
                                {loading && events.length === 0 ? (
                                    <div className="p-8 text-center text-gray-400">
                                        <ArrowPathIcon className="h-8 w-8 mx-auto mb-2 animate-spin" />
                                        <p>Loading detection feed...</p>
                                    </div>
                                ) : filteredEvents.length === 0 ? (
                                    <div className="p-12 text-center text-gray-400">
                                        <ShieldCheckIcon className="h-16 w-16 mx-auto mb-4 opacity-30" />
                                        <p className="text-lg font-medium">{isFiltered ? 'No events for this network' : 'No threats detected'}</p>
                                        <p className="text-sm mt-1">{isFiltered ? 'Try selecting "All Networks" to see all events.' : 'Monitoring is active. Events will appear here in real-time.'}</p>
                                    </div>
                                ) : (
                                    filteredEvents.map((event) => (
                                        <div
                                            key={event.eventId}
                                            className={`p-4 hover:bg-gray-50 transition-colors cursor-pointer ${getSeverityBg(event.severity)}`}
                                            onClick={() => setExpandedEvent(expandedEvent === event.eventId ? null : event.eventId)}
                                        >
                                            <div className="flex items-start justify-between">
                                                <div className="flex items-start space-x-3">
                                                    <div className="mt-1 flex-shrink-0">
                                                        {getThreatIcon(event.severity)}
                                                    </div>
                                                    <div>
                                                        <div className="flex items-center space-x-2">
                                                            <span className={`px-2 py-0.5 rounded text-xs font-bold text-white ${getSeverityColor(event.severity)}`}>
                                                                {getVerdictLabel(event.severity)}
                                                            </span>
                                                            <span className="text-sm text-gray-500">
                                                                {(() => {
                                                                    try {
                                                                        const d = event.detectedAt;
                                                                        let dateObj;
                                                                        if (Array.isArray(d)) {
                                                                            // Spring Boot LocalDateTime array format: [year, month, day, hour, minute, second, nano]
                                                                            dateObj = new Date(d[0], d[1] - 1, d[2], d[3], d[4], d[5]);
                                                                        } else {
                                                                            dateObj = new Date(d);
                                                                        }
                                                                        return dateObj.toLocaleTimeString();
                                                                    } catch (e) {
                                                                        return 'Unknown Time';
                                                                    }
                                                                })()}
                                                            </span>
                                                        </div>
                                                        <p className="mt-1 text-sm font-medium text-gray-900">
                                                            {event.severity === 'CRITICAL' || event.severity === 'HIGH'
                                                                ? 'Potential Deauth Attack Detected'
                                                                : event.severity === 'MEDIUM'
                                                                    ? 'Suspicious Activity'
                                                                    : 'Normal Disconnect'}
                                                        </p>
                                                        <div className="mt-1 text-xs text-gray-500 font-mono">
                                                            <span>Attacker MAC: <span className="text-red-600 font-mono">{event.realAttackerMac || event.attackerMac}</span>
                                                                {event.isSpoofed && <span className="ml-1 px-1 py-0.5 bg-yellow-100 text-yellow-700 rounded text-[10px]">SPOOFED</span>}
                                                            </span>
                                                            <span className="mx-2">|</span>
                                                            <span>Target BSSID: <span className="font-mono bg-gray-100 px-1 rounded">{event.targetBssid}</span></span>
                                                            <span className="mx-2">|</span>
                                                            <span>Score: <span className="font-bold">{event.totalScore || event.layer1Score}</span></span>
                                                        </div>
                                                    </div>
                                                </div>
                                                <div className="flex items-center gap-2">
                                                    <span className="text-xs text-gray-400">ID: {event.eventId}</span>
                                                    {expandedEvent === event.eventId ? (
                                                        <ChevronUpIcon className="h-4 w-4 text-gray-400" />
                                                    ) : (
                                                        <ChevronDownIcon className="h-4 w-4 text-gray-400" />
                                                    )}
                                                </div>
                                            </div>

                                            {/* Expanded Analysis Breakdown */}
                                            {expandedEvent === event.eventId && (
                                                <div className="mt-4 ml-8 p-4 bg-gray-100 rounded-lg text-sm">
                                                    <h4 className="font-semibold text-gray-700 mb-3">Heuristics Breakdown</h4>
                                                    <div className="grid grid-cols-2 gap-4">
                                                        <div>
                                                            <p className="text-gray-500">Rate Analysis</p>
                                                            <div className="flex items-center gap-2">
                                                                <div className="flex-1 bg-gray-200 rounded-full h-2">
                                                                    <div
                                                                        className="bg-blue-500 h-2 rounded-full"
                                                                        style={{ width: `${Math.min(((event.rateAnalyzerScore || 0) / 35) * 100, 100)}%` }}
                                                                    />
                                                                </div>
                                                                <span className="text-xs font-mono">{event.rateAnalyzerScore || 0}/35</span>
                                                            </div>
                                                        </div>
                                                        <div>
                                                            <p className="text-gray-500">Sequence Check</p>
                                                            <div className="flex items-center gap-2">
                                                                <div className="flex-1 bg-gray-200 rounded-full h-2">
                                                                    <div
                                                                        className="bg-purple-500 h-2 rounded-full"
                                                                        style={{ width: `${Math.min(((event.seqValidatorScore || 0) / 25) * 100, 100)}%` }}
                                                                    />
                                                                </div>
                                                                <span className="text-xs font-mono">{event.seqValidatorScore || 0}/25</span>
                                                            </div>
                                                        </div>
                                                        <div>
                                                            <p className="text-gray-500">Time Anomaly</p>
                                                            <div className="flex items-center gap-2">
                                                                <div className="flex-1 bg-gray-200 rounded-full h-2">
                                                                    <div
                                                                        className="bg-yellow-500 h-2 rounded-full"
                                                                        style={{ width: `${Math.min(((event.timeAnomalyScore || 0) / 15) * 100, 100)}%` }}
                                                                    />
                                                                </div>
                                                                <span className="text-xs font-mono">{event.timeAnomalyScore || 0}/15</span>
                                                            </div>
                                                        </div>
                                                        <div>
                                                            <p className="text-gray-500">Session State</p>
                                                            <div className="flex items-center gap-2">
                                                                <div className="flex-1 bg-gray-200 rounded-full h-2">
                                                                    <div
                                                                        className="bg-green-500 h-2 rounded-full"
                                                                        style={{ width: `${Math.min(((event.sessionStateScore || 0) / 20) * 100, 100)}%` }}
                                                                    />
                                                                </div>
                                                                <span className="text-xs font-mono">{event.sessionStateScore || 0}/20</span>
                                                            </div>
                                                        </div>
                                                    </div>
                                                    <div className="mt-4 pt-3 border-t border-gray-200">
                                                        <p className="text-gray-500">Heuristics Score</p>
                                                        <p className="text-2xl font-bold text-gray-900">{event.layer1Score}</p>
                                                    </div>
                                                </div>
                                            )}
                                        </div>
                                    ))
                                )}
                            </div>
                        </div>
                    </div>{/* end flex-1 (detection feed) */}

                    {/* P3-4: ML Insights Sidebar */}
                    <div className="w-72 flex-shrink-0">
                        <MLInsightsCard />
                    </div>
                </div>{/* end flex layout */}

                {/* Back to Dashboard */}
                <div className="mt-8 text-center">
                    <Button
                        variant="ghost"
                        onClick={() => navigate(-1)}
                    >
                        ← Back to Dashboard
                    </Button>
                </div>
            </main>
        </div>
    );
};

export default DetectionMonitor;
