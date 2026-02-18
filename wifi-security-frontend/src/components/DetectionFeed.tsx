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

    // Fetch initial events from database
    const fetchInitialEvents = async () => {
        setLoading(true);
        setEvents([]); // Clear existing events before fetching
        const response = await detectionService.getRecentEvents();
        if (response.success && response.data) {
            setEvents(response.data);
        }
        setLoading(false);
    };

    useEffect(() => {
        fetchInitialEvents();
    }, [refreshTrigger]); // Re-fetch when refreshTrigger changes

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

    if (loading && events.length === 0) {
        return <div className="p-4 text-center text-gray-500">Loading detection feed...</div>;
    }

    return (
        <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
            <div className="px-6 py-4 border-b border-gray-100 flex justify-between items-center bg-gray-50">
                <h3 className="text-lg font-semibold text-gray-800">Real-Time Threat Detection</h3>
                <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                    <span className="w-2 h-2 mr-1.5 bg-green-400 rounded-full animate-pulse"></span>
                    Live
                </span>
            </div>

            <div className="divide-y divide-gray-100 max-h-[400px] overflow-y-auto">
                {events.length === 0 ? (
                    <div className="p-8 text-center text-gray-400">
                        <ShieldExclamationIcon className="h-12 w-12 mx-auto mb-2 opacity-50" />
                        <p>No threats detected yet. Monitoring active.</p>
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
