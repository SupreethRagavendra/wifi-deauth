import { useState, useEffect, useCallback } from 'react';

// Use environment variable or default to localhost:8080
const BACKEND_URL = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8080';

export interface LiveStatus {
    systemStatus: string;
    activeThreats: number;
    threatsLastHour: number;
    underAttack: boolean;
    timestamp: string;
}

export function useLiveStatus() {
    const [liveStatus, setLiveStatus] = useState<LiveStatus>({
        systemStatus: 'SAFE',
        activeThreats: 0,
        threatsLastHour: 0,
        underAttack: false,
        timestamp: new Date().toISOString()
    });
    const [lastError, setLastError] = useState<string | null>(null);

    const fetchLiveStatus = useCallback(async () => {
        try {
            const response = await fetch(`${BACKEND_URL}/api/detection/live-status`);
            if (response.ok) {
                const data = await response.json();
                setLiveStatus(data);
                setLastError(null);
            } else {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
        } catch (error) {
            console.error('Failed to fetch live status:', error);
            setLastError(error instanceof Error ? error.message : 'Unknown error');
        }
    }, []);

    useEffect(() => {
        // Initial fetch
        fetchLiveStatus();

        // Poll every 3 seconds
        const interval = setInterval(fetchLiveStatus, 3000);

        return () => clearInterval(interval);
    }, [fetchLiveStatus]);

    return {
        ...liveStatus,
        lastError,
        refresh: fetchLiveStatus
    };
}
