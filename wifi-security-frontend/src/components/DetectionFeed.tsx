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
    const [threatLevel, setThreatLevel] = useState('SAFE');
    const [activeThreats, setActiveThreats] = useState(0);
    const [underAttack, setUnderAttack] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [lastFetch, setLastFetch] = useState<string | null>(null);

    // Fetch threat level
    const fetchThreatLevel = async () => {
        try {
            const res = await detectionService.getThreatLevel();
            if (res.success && res.data) {
                setThreatLevel(res.data.threatLevel);
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
                <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                    underAttack ? 'bg-red-100 text-red-800' : 'bg-green-100 text-green-800'
                }`}>
                    <span className={`w-2 h-2 mr-1.5 rounded-full animate-pulse ${
                        underAttack ? 'bg-red-400' : 'bg-green-400'
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
                    events.map((event) => (
                        <div key={event.eventId} className="p-4 hover:bg-gray-50 transition-colors duration-150">
                            <div className="flex items-start justify-between">
                                <div className="flex items-start space-x-3">
                                    <div className="mt-1 flex-shrink-0">
                                        {getThreatIcon(event.severity)}
                                    </div>
                                    <div>
                                        <div className="flex items-center space-x-2">
                                            <span className={`px-2 py-0.5 rounded text-xs font-semibold ${getSeverityColor(event.severity)}`}>
                                                {event.severity}
                                            </span>
                                            <span className="text-sm text-gray-500">
                                                {new Date(event.detectedAt).toLocaleTimeString()}
                                            </span>
                                        </div>
                                        <p className="mt-1 text-sm font-medium text-gray-900">
                                            Potential Deauth Attack Detected
                                        </p>
                                        <div className="mt-1 text-xs text-gray-500 font-mono space-y-1">
                                            <p>Source: <span className="text-red-500">{event.attackerMac}</span></p>
                                            <p>Target: <span>{event.targetBssid}</span></p>
                                            <p>Score: {event.layer1Score}/100</p>
                                            {event.mlConfidence !== undefined && (
                                                <p className="flex items-center gap-1">
                                                    <span>AI Confidence:</span>
                                                    <span className={`font-bold ${event.mlConfidence > 75 ? 'text-red-600' : 'text-gray-600'}`}>
                                                        {event.mlConfidence}%
                                                    </span>
                                                </p>
                                            )}
                                        </div>
                                    </div>
                                </div>
                                <div className="text-right">
                                    <div className="text-xs text-gray-400">
                                        ID: {event.eventId}
                                    </div>
                                </div>
                            </div>
                        </div>
                    ))
                )}
            </div>
        </div>
    );
};
