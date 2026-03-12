import { useState, useEffect, useCallback } from 'react';
import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8080/api';

// Short-timeout axios for polling (3s timeout instead of 30s)
const pollAxios = axios.create({ timeout: 5000 });

export interface DetectionStats {
    total_packets: number;
    total_events: number;
    attack_events: number;
    critical_events: number;
    suspicious_events: number;
    current_status: string;
    active_events: number;
    attacks_1hr: number;
    ml_models_loaded: number;
    avg_confidence: number;
    agreement_rate: number;
}

export interface DeauthEvent {
    id: number;
    src_mac: string;
    dst_mac: string;
    bssid: string;
    rssi: number | null;
    first_seen: string;
    last_seen: string;
    packet_count: number;
    rate_score: number;
    ml_score: number;
    physical_score: number;
    final_score: number;
    verdict: string;
    ml_agreement: number;
    resolved: number;
}

const defaultStats: DetectionStats = {
    total_packets: 0,
    total_events: 0,
    attack_events: 0,
    critical_events: 0,
    suspicious_events: 0,
    current_status: 'LOADING',
    active_events: 0,
    attacks_1hr: 0,
    ml_models_loaded: 0,
    avg_confidence: 0,
    agreement_rate: 0,
};

export function useDetectionStats(pollIntervalMs: number = 3000) {
    const [stats, setStats] = useState<DetectionStats>(defaultStats);
    const [events, setEvents] = useState<DeauthEvent[]>([]);
    const [loading, setLoading] = useState(true);

    const fetchStats = useCallback(async () => {
        try {
            const token = localStorage.getItem('wifi_shield_token');
            const headers: Record<string, string> = {};
            if (token) headers['Authorization'] = `Bearer ${token}`;

            const res = await pollAxios.get(`${API_URL}/detection/stats`, { headers });
            if (res.data) {
                setStats(res.data);
            }
        } catch {
            // Detection service offline — keep last known stats
        }
    }, []);

    const fetchEvents = useCallback(async () => {
        try {
            const token = localStorage.getItem('wifi_shield_token');
            const headers: Record<string, string> = {};
            if (token) headers['Authorization'] = `Bearer ${token}`;

            const res = await pollAxios.get(`${API_URL}/detection/events?limit=50`, { headers });
            setEvents(res.data || []);
        } catch {
            // Keep last known events
        }
    }, []);

    const clearHistory = useCallback(async (): Promise<boolean> => {
        try {
            const token = localStorage.getItem('wifi_shield_token');
            const headers: Record<string, string> = {};
            if (token) headers['Authorization'] = `Bearer ${token}`;

            const res = await pollAxios.post(`${API_URL}/detection/clear`, {}, { headers });
            if (res.data?.success) {
                setStats(prev => ({ ...prev, total_events: 0, attack_events: 0, critical_events: 0, suspicious_events: 0, active_events: 0 }));
                setEvents([]);
                return true;
            }
            return false;
        } catch {
            return false;
        }
    }, []);

    const resolveAll = useCallback(async (): Promise<boolean> => {
        try {
            const token = localStorage.getItem('wifi_shield_token');
            const headers: Record<string, string> = {};
            if (token) headers['Authorization'] = `Bearer ${token}`;

            const res = await pollAxios.post(`${API_URL}/detection/resolve`, {}, { headers });
            if (res.data?.success) {
                await fetchStats();
                await fetchEvents();
                return true;
            }
            return false;
        } catch {
            return false;
        }
    }, [fetchStats, fetchEvents]);

    useEffect(() => {
        // Initial fetch
        const init = async () => {
            await Promise.all([fetchStats(), fetchEvents()]);
            setLoading(false);
        };
        init();

        // Poll
        const interval = setInterval(() => {
            fetchStats();
            fetchEvents();
        }, pollIntervalMs);

        return () => clearInterval(interval);
    }, [fetchStats, fetchEvents, pollIntervalMs]);

    return { stats, events, loading, clearHistory, resolveAll, fetchStats, fetchEvents };
}
