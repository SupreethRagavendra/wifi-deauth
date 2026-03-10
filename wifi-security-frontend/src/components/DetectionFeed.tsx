import React, { useEffect, useState } from 'react';
import { detectionService } from '../services/api';
import { DetectionEvent } from '../types';
import {
    ExclamationTriangleIcon,
    ShieldExclamationIcon,
    CheckCircleIcon
} from '@heroicons/react/24/solid';

interface DetectionFeedProps {
    refreshTrigger?: number; // Change this value to force refresh
}

export const DetectionFeed: React.FC<DetectionFeedProps> = ({ refreshTrigger }) => {
    const [events, setEvents] = useState<DetectionEvent[]>([]);
    const [loading, setLoading] = useState(true);
    const [activeThreats, setActiveThreats] = useState(0);
    const [underAttack, setUnderAttack] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [lastFetch, setLastFetch] = useState<string | null>(null);

    // Fetch threat level
    const fetchThreatLevel = async () => {
        try {
            const res = await detectionService.getThreatLevel();
            if (res.success && res.data) {
                setActiveThreats(res.data.activeThreats);
                setUnderAttack(res.data.underAttack);
                setError(null);
            } else {
                setError(res.error || 'Failed to fetch threat level');
            }
        } catch (err) {
            setError('Backend connection error');
            console.error('Threat level fetch error:', err);
        }
    };

    // Fetch initial events from database
    const fetchInitialEvents = async () => {
        setLoading(true);
        setEvents([]); // Clear existing events before fetching
        setError(null);

        try {
            await Promise.all([
                fetchThreatLevel(),
                (async () => {
                    const response = await detectionService.getRecentEvents();
                    if (response.success && response.data) {
                        setEvents(response.data);
                        setLastFetch(new Date().toLocaleTimeString());
                        console.log(`✅ Fetched ${response.data.length} events from backend`);
                    } else {
                        setError(response.error || 'Failed to fetch events');
                        console.error('❌ Failed to fetch events:', response.error);
                    }
                })()
            ]);
        } catch (err) {
            setError('Connection error - is backend running?');
            console.error('❌ Connection error:', err);
        }

        setLoading(false);
    };

    useEffect(() => {
        fetchInitialEvents();

        // Polling interval (3 seconds)
        const intervalId = setInterval(() => {
            fetchSilentEvents();
            fetchThreatLevel();
        }, 3000);

        return () => clearInterval(intervalId);
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [refreshTrigger]); // Re-fetch when refreshTrigger changes

    // Silent fetch for polling (doesn't set loading state)
    const fetchSilentEvents = async () => {
        try {
            const response = await detectionService.getRecentEvents();
            if (response.success && response.data) {
                setEvents(response.data);
                setLastFetch(new Date().toLocaleTimeString());
                setError(null);
            } else {
                setError(response.error || 'Failed to fetch events');
            }
        } catch (err) {
            setError('Backend connection error');
            console.error('Silent fetch error:', err);
        }
    };

    const getSeverityColor = (level: string) => {
        switch (level) {
            case 'CRITICAL': return 'bg-red-100 text-red-800 border-red-200';
            case 'HIGH': return 'bg-orange-100 text-orange-800 border-orange-200';
            case 'MEDIUM': return 'bg-yellow-100 text-yellow-800 border-yellow-200';
            default: return 'bg-green-100 text-green-800 border-green-200';
        }
    };

    const getThreatIcon = (level: string) => {
        if (level === 'CRITICAL' || level === 'HIGH') return <ShieldExclamationIcon className="h-5 w-5 text-red-600" />;
        if (level === 'MEDIUM') return <ExclamationTriangleIcon className="h-5 w-5 text-yellow-600" />;
        return <CheckCircleIcon className="h-5 w-5 text-green-600" />;
    };

    if (loading) {
        return <div className="p-4 text-center text-gray-500">Loading detection feed...</div>;
    }

    if (error) {
        return (
            <div className="p-4 text-center">
                <ShieldExclamationIcon className="h-12 w-12 mx-auto mb-2 text-red-500" />
                <p className="text-red-600 font-medium">Connection Error</p>
                <p className="text-sm text-gray-600 mt-1">{error}</p>
                <p className="text-xs text-gray-400 mt-2">Last fetch: {lastFetch || 'Never'}</p>
                <button
                    onClick={fetchInitialEvents}
                    className="mt-3 px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors"
                >
                    Retry Connection
                </button>
            </div>
        );
    }

    return (
        <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
            <div className="px-6 py-4 border-b border-gray-100 flex justify-between items-center bg-gray-50">
                <h3 className="text-lg font-semibold text-gray-800">Real-Time Threat Detection</h3>
                <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${underAttack ? 'bg-red-100 text-red-800' : 'bg-green-100 text-green-800'
                    }`}>
                    <span className={`w-2 h-2 mr-1.5 rounded-full animate-pulse ${underAttack ? 'bg-red-400' : 'bg-green-400'
                        }`}></span>
                    {underAttack ? 'UNSAFE' : 'SAFE'} ({activeThreats} threats)
                </span>
            </div>

            <div className="divide-y divide-gray-100 max-h-[400px] overflow-y-auto">
                {events.length === 0 ? (
                    <div className="p-8 text-center text-gray-400">
                        <ShieldExclamationIcon className="h-12 w-12 mx-auto mb-2 opacity-50" />
                        <p className="font-medium">No threats detected yet</p>
                        <p className="text-sm mt-1">Monitoring active</p>
                        <p className="text-xs text-gray-300 mt-2">Last fetch: {lastFetch || 'Never'}</p>
                        <p className="text-xs text-gray-300">Backend: {underAttack ? 'UNSAFE' : 'SAFE'}</p>
                        <button
                            onClick={fetchInitialEvents}
                            className="mt-3 px-3 py-1 bg-gray-100 text-gray-600 rounded hover:bg-gray-200 transition-colors text-sm"
                        >
                            Refresh
                        </button>
                    </div>
                ) : (
                    events.map((event) => {
                        const scorePercent = event.totalScore || event.layer1Score;
                        const severityClass = getSeverityColor(event.severity);

                        return (
                            <div key={event.eventId} className="p-5 hover:bg-slate-50 transition-all duration-300 border-b border-slate-100 last:border-b-0 group">
                                <div className="flex items-start justify-between">
                                    <div className="flex items-start gap-4">
                                        <div className={`mt-1 flex-shrink-0 p-2 rounded-lg bg-white shadow-sm ring-1 ring-slate-100 group-hover:scale-110 transition-transform duration-300`}>
                                            {getThreatIcon(event.severity)}
                                        </div>
                                        <div className="flex flex-col flex-1">
                                            <div className="flex items-center gap-3">
                                                <h4 className="text-[15px] font-bold text-slate-900 group-hover:text-blue-700 transition-colors">
                                                    Potential Deauth Attack Detected
                                                </h4>
                                                <span className={`px-2.5 py-0.5 rounded text-[10px] uppercase font-bold tracking-widest ${severityClass}`}>
                                                    {event.severity}
                                                </span>
                                            </div>

                                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-2 mt-3 p-3 bg-white rounded-lg border border-slate-100 shadow-sm">
                                                <div className="flex flex-col">
                                                    <span className="text-[10px] uppercase font-semibold text-slate-400 tracking-wider">
                                                        {event.attackerMac === event.targetBssid ? "Spoofed AP (Source)" : "Source MAC"}
                                                    </span>
                                                    <span className="font-mono text-sm font-bold text-red-600">{event.attackerMac}</span>
                                                </div>
                                                <div className="flex flex-col">
                                                    <span className="text-[10px] uppercase font-semibold text-slate-400 tracking-wider">
                                                        {event.targetMac ? "Target Client" : "Target BSSID"}
                                                    </span>
                                                    <span className="font-mono text-sm font-medium text-slate-700">
                                                        {event.targetMac || event.targetBssid}
                                                    </span>
                                                </div>
                                            </div>

                                            <div className="flex flex-wrap items-center gap-2 mt-3 text-[11px] font-medium text-slate-600">
                                                <div className="flex items-center gap-1.5 px-2.5 py-1 bg-white border border-slate-200 rounded-md shadow-sm">
                                                    <span className="text-slate-400">Heuristics:</span>
                                                    <span className="text-slate-800 font-bold">{event.layer1Score}</span>
                                                </div>
                                                <div className="flex items-center gap-1.5 px-2.5 py-1 bg-white border border-slate-200 rounded-md shadow-sm">
                                                    <span className="text-slate-400">AI Analysis:</span>
                                                    <span className="text-slate-800 font-bold">{event.layer2Score || 0}</span>
                                                </div>
                                                {(event.layer3Score !== undefined && event.layer3Score !== null && event.layer3Score > 0) && (
                                                    <div className="flex items-center gap-1.5 px-2.5 py-1 bg-emerald-50 border border-emerald-100 rounded-md shadow-sm">
                                                        <span className="text-emerald-600 font-semibold">Physical:</span>
                                                        <span className="text-emerald-800 font-bold">{event.layer3Score}</span>
                                                    </div>
                                                )}
                                                <div className="flex items-center gap-1.5 px-3 py-1 bg-slate-900 text-white rounded-md shadow-sm ml-auto sm:ml-0">
                                                    <span>Threat Score:</span>
                                                    <span className="font-bold text-amber-400">{scorePercent}</span>
                                                </div>
                                            </div>

                                            {(event.mlConfidence !== undefined && event.mlConfidence !== null) && (
                                                <div className="mt-4 space-y-2 bg-slate-50 p-3 rounded-lg border border-slate-100">
                                                    <div className="flex justify-between items-center text-[11px] font-sans">
                                                        <div className="flex items-center gap-2">
                                                            <span className="font-semibold text-slate-700">AI Confidence: {(event.mlConfidence * 100).toFixed(0)}%</span>
                                                            {event.modelAgreement && (
                                                                <span className="text-slate-400 font-medium tracking-wide">({event.modelAgreement} models agree)</span>
                                                            )}
                                                        </div>
                                                        {event.mlPrediction && (
                                                            <span className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold tracking-wider ${event.mlPrediction.toLowerCase() === 'attack'
                                                                ? event.mlConfidence > 0.90 ? 'bg-red-500 text-white shadow-sm' : 'bg-orange-500 text-white shadow-sm'
                                                                : 'bg-emerald-500 text-white shadow-sm'
                                                                }`}>
                                                                {event.mlPrediction}
                                                            </span>
                                                        )}
                                                    </div>

                                                    <div className="w-full h-1.5 bg-slate-200 rounded-full overflow-hidden">
                                                        <div
                                                            className={`h-full transition-all duration-1000 ease-out ${event.mlConfidence > 0.8 ? 'bg-gradient-to-r from-red-500 to-red-600' : event.mlConfidence > 0.5 ? 'bg-gradient-to-r from-orange-400 to-orange-500' : 'bg-gradient-to-r from-emerald-400 to-emerald-500'}`}
                                                            style={{ width: `${Math.round(event.mlConfidence * 100)}%` }}
                                                        ></div>
                                                    </div>
                                                </div>
                                            )}

                                            {(event.layer3Notes) && (
                                                <div className="mt-3 bg-amber-50/80 border border-amber-200/60 p-3 rounded-lg shadow-sm">
                                                    <div className="flex flex-col gap-1.5 text-[11px]">
                                                        <span className="font-bold text-amber-900 uppercase tracking-wider text-[10px] flex items-center gap-1">
                                                            <svg className="w-3 h-3 text-amber-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                                                            </svg>
                                                            Device Signal Check
                                                        </span>
                                                        <span className="text-amber-800 font-medium">{event.layer3Notes}</span>
                                                    </div>
                                                </div>
                                            )}
                                        </div>
                                    </div>
                                    <div className="flex flex-col items-end pl-4">
                                        <span className="text-xs font-semibold text-slate-400">
                                            {new Date(event.detectedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                                        </span>
                                        <div className="mt-1 text-[10px] font-mono text-slate-300">
                                            ID: {event.eventId}
                                        </div>
                                    </div>
                                </div>
                            </div>
                        );
                    })
                )}
            </div>
        </div>
    );
};

export default DetectionFeed;
