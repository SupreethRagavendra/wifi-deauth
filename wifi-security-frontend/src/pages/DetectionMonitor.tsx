import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { detectionService, wifiService } from '../services/api';
import { DetectionEvent, WiFiNetwork } from '../types';
import { useDetectionStatus, Alert } from '../hooks/useDetectionStatus';
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

export const DetectionMonitor: React.FC = () => {
    const navigate = useNavigate();
    const { user, logout } = useAuth();
    const { latestAlert, connected } = useDetectionStatus();

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

    // Fetch threat level
    const fetchThreatLevel = async () => {
        const res = await detectionService.getThreatLevel();
        if (res.success && res.data) {
            setThreatLevel(res.data.threatLevel);
            setActiveThreats(res.data.activeThreats);
            setUnderAttack(res.data.underAttack);
        }
    };

    // Initial fetch of events
    useEffect(() => {
        const fetchInitialEvents = async () => {
            await Promise.all([
                fetchThreatLevel(),
                (async () => {
                    const response = await detectionService.getRecentEvents();
                    if (response.success && response.data) {
                        setEvents(response.data);
                    }
                    setLoading(false);
                })()
            ]);
        };
        fetchInitialEvents();

        // Poll threat level every 3 seconds
        const threatInterval = setInterval(fetchThreatLevel, 3000);
        return () => clearInterval(threatInterval);
    }, []);

    // Sync incoming individual real-time events alongside the historical DB events
    useEffect(() => {
        if (latestAlert) {
            const newEvent: DetectionEvent = {
                eventId: Math.floor(Math.random() * 1000000), // temp ID
                attackerMac: latestAlert.attackerMac,
                targetBssid: latestAlert.targetBssid,
                layer1Score: latestAlert.packetCount,
                severity: latestAlert.severity as any,
                detectedAt: latestAlert.timestamp || new Date().toISOString(),
                attackType: latestAlert.type
            };
            setEvents(prev => {
                // Prevent duplicate fast-firing identical timestamps (optional safety)
                if (prev.some(e => e.detectedAt === newEvent.detectedAt && e.attackerMac === newEvent.attackerMac)) {
                    return prev;
                }
                return [newEvent, ...prev].slice(0, 1000); // keep up to 1000 items in memory
            });
        }
    }, [latestAlert]);

    // Stats calculations - ACTIVE threats only (last 60 seconds)
    const stats = {
        total: events.length, // Only recent events now
        active: events.filter(e => {
            const eventTime = new Date(e.detectedAt).getTime();
            const now = Date.now();
            return (now - eventTime) < 60000; // Last 60 sec
        }).length,
        normal: events.filter(e => e.severity === 'LOW').length,
        suspicious: events.filter(e => e.severity === 'MEDIUM').length,
        attacks: events.filter(e => e.severity === 'HIGH' || e.severity === 'CRITICAL').length,
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
            {/* Header */}
            <header className="bg-white border-b border-gray-200">
                <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
                    <div className="flex h-16 items-center justify-between">
                        <div className="flex items-center gap-3">
                            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-blue-600">
                                <ShieldCheckIcon className="h-5 w-5 text-white" />
                            </div>
                            <span className="text-xl font-bold text-gray-900">
                                WiFi Shield - Detection Monitor
                            </span>
                        </div>

                        <div className="flex items-center gap-4">
                            <span className="text-sm text-gray-500">
                                Welcome, <span className="font-semibold text-gray-900">{user?.name}</span>
                            </span>
                            <button
                                onClick={handleLogout}
                                className="text-sm font-medium text-gray-500 hover:text-gray-900"
                            >
                                Logout
                            </button>
                        </div>
                    </div>
                </div>
            </header>

            {/* Main Content */}
            <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
                {/* Status Banner */}
                {underAttack && (
                    <div className="mb-8 p-4 rounded-xl border-2 bg-red-50 border-red-200">
                        <div className="flex items-center justify-between">
                            <div className="flex items-center gap-3">
                                <ShieldExclamationIcon className="h-8 w-8 text-red-600" />
                                <div>
                                    <h2 className="text-xl font-bold text-red-800">
                                        🚨 UNDER ATTACK
                                    </h2>
                                    <p className="text-sm text-red-600">
                                        Threat Level: {threatLevel} | Active Threats: {activeThreats}
                                    </p>
                                </div>
                            </div>
                            <div className="px-3 py-1 rounded-full text-sm font-medium bg-red-100 text-red-800">
                                ATTACK DETECTED
                            </div>
                        </div>
                    </div>
                )}

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
                <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-4 mb-8">
                    <div className="bg-white rounded-xl p-6 shadow-sm border border-gray-100">
                        <div className="flex items-center justify-between">
                            <div>
                                <p className="text-xs font-semibold uppercase tracking-wider text-gray-400">Active Events</p>
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
                                <p className="text-xs font-semibold uppercase tracking-wider text-gray-400">Normal</p>
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
                                <p className="text-xs font-semibold uppercase tracking-wider text-gray-400">Suspicious</p>
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
                                <p className="text-xs font-semibold uppercase tracking-wider text-gray-400">Attacks</p>
                                <p className="mt-2 text-3xl font-bold text-red-600">{stats.attacks}</p>
                            </div>
                            <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-red-100">
                                <ShieldExclamationIcon className="h-6 w-6 text-red-600" />
                            </div>
                        </div>
                    </div>
                </div>

                {/* Live Detection Feed */}
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
                        ) : events.length === 0 ? (
                            <div className="p-12 text-center text-gray-400">
                                <ShieldCheckIcon className="h-16 w-16 mx-auto mb-4 opacity-30" />
                                <p className="text-lg font-medium">No threats detected</p>
                                <p className="text-sm mt-1">Monitoring is active. Events will appear here in real-time.</p>
                            </div>
                        ) : (
                            events.map((event) => (
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
                                                        {new Date(event.detectedAt).toLocaleTimeString()}
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
                                                    <span>Spoofed MAC: <span className="text-red-600 font-mono">{event.attackerMac}</span></span>
                                                    <span className="mx-2">|</span>
                                                    <span>Target BSSID: <span className="font-mono bg-gray-100 px-1 rounded">{event.targetBssid}</span></span>
                                                    <span className="mx-2">|</span>
                                                    <span>Score: <span className="font-bold">{event.layer1Score}</span>/100</span>
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

                                    {/* Expanded Layer Breakdown */}
                                    {expandedEvent === event.eventId && (
                                        <div className="mt-4 ml-8 p-4 bg-gray-100 rounded-lg text-sm">
                                            <h4 className="font-semibold text-gray-700 mb-3">Layer 1 Breakdown</h4>
                                            <div className="grid grid-cols-2 gap-4">
                                                <div>
                                                    <p className="text-gray-500">Rate Analysis</p>
                                                    <div className="flex items-center gap-2">
                                                        <div className="flex-1 bg-gray-200 rounded-full h-2">
                                                            <div
                                                                className="bg-blue-500 h-2 rounded-full"
                                                                style={{ width: `${Math.min((event.layer1Score / 100) * 100, 100)}%` }}
                                                            />
                                                        </div>
                                                        <span className="text-xs font-mono">{Math.round(event.layer1Score * 0.35)}/35</span>
                                                    </div>
                                                </div>
                                                <div>
                                                    <p className="text-gray-500">Sequence Check</p>
                                                    <div className="flex items-center gap-2">
                                                        <div className="flex-1 bg-gray-200 rounded-full h-2">
                                                            <div
                                                                className="bg-purple-500 h-2 rounded-full"
                                                                style={{ width: `${Math.min((event.layer1Score / 100) * 100, 100)}%` }}
                                                            />
                                                        </div>
                                                        <span className="text-xs font-mono">{Math.round(event.layer1Score * 0.25)}/25</span>
                                                    </div>
                                                </div>
                                                <div>
                                                    <p className="text-gray-500">Time Anomaly</p>
                                                    <div className="flex items-center gap-2">
                                                        <div className="flex-1 bg-gray-200 rounded-full h-2">
                                                            <div
                                                                className="bg-yellow-500 h-2 rounded-full"
                                                                style={{ width: `${Math.min((event.layer1Score / 100) * 80, 100)}%` }}
                                                            />
                                                        </div>
                                                        <span className="text-xs font-mono">{Math.round(event.layer1Score * 0.15)}/15</span>
                                                    </div>
                                                </div>
                                                <div>
                                                    <p className="text-gray-500">Session State</p>
                                                    <div className="flex items-center gap-2">
                                                        <div className="flex-1 bg-gray-200 rounded-full h-2">
                                                            <div
                                                                className="bg-green-500 h-2 rounded-full"
                                                                style={{ width: `${Math.min((event.layer1Score / 100) * 60, 100)}%` }}
                                                            />
                                                        </div>
                                                        <span className="text-xs font-mono">{Math.round(event.layer1Score * 0.20)}/20</span>
                                                    </div>
                                                </div>
                                            </div>
                                            <div className="mt-4 pt-3 border-t border-gray-200">
                                                <p className="text-gray-500">Combined Score</p>
                                                <p className="text-2xl font-bold text-gray-900">{event.layer1Score}/100</p>
                                            </div>
                                        </div>
                                    )}
                                </div>
                            ))
                        )}
                    </div>
                </div>

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
