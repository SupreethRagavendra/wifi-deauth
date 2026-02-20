import { useState, useEffect, useCallback, useRef } from 'react';

// Use environment variable or default to localhost:8080
const BACKEND_URL = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8080';

export interface AttackDetail {
    attackerMac: string;
    targetBssid: string;
    packetCount: number;
    signal: number;
    channel: number;
    reason: number;
    detectedAt: string;
    frameType: string;
}

export interface Alert {
    type: string;
    severity: string;
    message: string;
    attackerMac: string;
    targetBssid: string;
    packetCount: number;
    timestamp: string;
}

export function useDetectionStatus() {
    const [status, setStatus] = useState<'SAFE' | 'UNSAFE' | 'UNKNOWN'>('UNKNOWN');
    const [isUnderAttack, setIsUnderAttack] = useState(false);
    const [latestAlert, setLatestAlert] = useState<Alert | null>(null);
    const [attackDetails, setAttackDetails] = useState<AttackDetail[]>([]);
    const [alerts, setAlerts] = useState<Alert[]>([]);
    const [totalPackets, setTotalPackets] = useState<number>(0);
    const [totalThreats, setTotalThreats] = useState<number>(0);
    const [lastUpdated, setLastUpdated] = useState<string | null>(null);
    const [connected, setConnected] = useState<boolean>(false);
    const eventSourceRef = useRef<EventSource | null>(null);

    // Fetch status via REST (fallback / initial)
    const fetchStatus = useCallback(async () => {
        try {
            const endpoints = [
                '/api/detection/status',
                '/api/networks/status'
            ];

            for (const endpoint of endpoints) {
                try {
                    const resp = await fetch(`${BACKEND_URL}${endpoint}`);
                    if (resp.ok) {
                        const data = await resp.json();
                        updateFromData(data);
                        return;
                    }
                } catch (e) {
                    continue;
                }
            }
        } catch (error) {
            console.error('Failed to fetch detection status:', error);
        }
    }, []);

    // Fetch recent alerts
    const fetchAlerts = useCallback(async () => {
        try {
            const resp = await fetch(`${BACKEND_URL}/api/detection/alerts`);
            if (resp.ok) {
                const data = await resp.json();
                setAlerts(data);
            }
        } catch (error) {
            console.error('Failed to fetch alerts:', error);
        }
    }, []);

    const updateFromData = (data: any) => {
        if (data.status) {
            setStatus(data.status);
            setIsUnderAttack(data.status === 'UNSAFE');
        }
        if (data.isUnderAttack !== undefined) {
            setIsUnderAttack(data.isUnderAttack);
            setStatus(data.isUnderAttack ? 'UNSAFE' : 'SAFE');
        }
        if (data.attackDetails) {
            setAttackDetails(data.attackDetails);
        }
        if (data.totalPackets !== undefined) {
            setTotalPackets(data.totalPackets);
        }
        if (data.totalThreats !== undefined) {
            setTotalThreats(data.totalThreats);
        }
        if (data.lastUpdated) {
            setLastUpdated(data.lastUpdated);
        }
        if (data.activeAlerts) {
            setAlerts(data.activeAlerts);
        }
    };

    // SSE connection for real-time updates
    useEffect(() => {
        let retryTimeout: NodeJS.Timeout;

        const connectSSE = () => {
            console.log('Connecting to SSE stream...');
            const eventSource = new EventSource(`${BACKEND_URL}/api/detection/stream`);
            eventSourceRef.current = eventSource;

            eventSource.onopen = () => {
                console.log('SSE connected');
                setConnected(true);
            };

            eventSource.addEventListener('status', (event: MessageEvent) => {
                try {
                    const data = JSON.parse(event.data);
                    // console.log('SSE status update:', data);
                    updateFromData(data);
                } catch (e) {
                    console.error('Failed to parse SSE status:', e);
                }
            });

            eventSource.addEventListener('alert', (event: MessageEvent) => {
                try {
                    const alert = JSON.parse(event.data);
                    // console.log('SSE alert:', alert);
                    setLatestAlert(alert);
                    setIsUnderAttack(true);
                    setStatus('UNSAFE');
                    setTotalThreats(prev => prev + 1); // Increment local counter on new alert
                } catch (e) {
                    console.error('Failed to parse SSE alert:', e);
                }
            });

            eventSource.onerror = (error) => {
                // console.error('SSE error:', error);
                setConnected(false);
                eventSource.close();

                // Retry after 5 seconds
                retryTimeout = setTimeout(connectSSE, 5000);
            };
        };

        connectSSE();

        // Also poll every 2 seconds as backup for faster updates
        const pollInterval = setInterval(() => {
            fetchStatus();
        }, 2000);

        return () => {
            if (eventSourceRef.current) {
                eventSourceRef.current.close();
            }
            clearTimeout(retryTimeout);
            clearInterval(pollInterval);
        };
    }, [fetchStatus]);

    // Initial fetch
    useEffect(() => {
        fetchStatus();
        fetchAlerts();
    }, [fetchStatus, fetchAlerts]);

    return {
        status,
        latestAlert,
        isUnderAttack,
        attackDetails, // Assuming 'activeThreats' was meant to be 'attackDetails'
        totalThreats,
        connected,
        alerts, // Keep alerts for historical view
        totalPackets,
        lastUpdated,
        refresh: fetchStatus
    };
}
