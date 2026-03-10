import React, { useEffect, useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { AppNavbar } from '../components/layout/AppNavbar';
import { Card } from '../components/ui';
import api from '../services/api';
import {
    ShieldCheckIcon,
    WifiIcon,
    UsersIcon,
    SignalIcon,
    ExclamationTriangleIcon,
    ArrowPathIcon
} from '@heroicons/react/24/outline';

interface DashboardStats {
    activeSsid: string;
    activeBssid: string;
    networkStatus: string;
    threatLevel: string;
    connectedClientsCount: number;
    apSignalStrength: string;
    securityMode: string;
    speed: string;
    isDeviceConnected: boolean;
}

export const ViewerDashboard: React.FC = () => {
    const { user } = useAuth();
    const [stats, setStats] = useState<DashboardStats | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');

    // Async client count
    const [clientCount, setClientCount] = useState<number | null>(null);
    const [loadingClients, setLoadingClients] = useState(false);

    const fetchStats = async () => {
        try {
            setLoading(true);
            const response = await api.get('/wifi/faculty/dashboard');
            setStats(response.data);
            setError('');
        } catch (err) {
            console.error('Failed to fetch dashboard stats:', err);
            setError('Failed to load network statistics');
        } finally {
            setLoading(false);
        }
    };

    const fetchClientCount = async () => {
        setLoadingClients(true);
        try {
            const response = await api.get('/wifi/faculty/clients');
            const clients = response.data;
            setClientCount(Array.isArray(clients) ? clients.length : 0);
        } catch (err) {
            console.error('Failed to fetch client count:', err);
            setClientCount(0);
        } finally {
            setLoadingClients(false);
        }
    };

    useEffect(() => {
        fetchStats();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    // Fetch client count async after page loads
    useEffect(() => {
        if (stats && !loading) {
            fetchClientCount();
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [stats, loading]);

    if (loading && !stats) {
        return (
            <div className="flex justify-center items-center min-h-screen bg-background-primary">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
            </div>
        );
    }

    return (
        <div className="min-h-screen bg-background-primary">
            <AppNavbar />

            {/* Main Content */}
            <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
                {/* Header */}
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between mb-8">
                    <div>
                        <h1 className="text-h1 text-text-primary">
                            Welcome, {user?.name || 'Viewer'}
                        </h1>
                        <p className="mt-1 text-body text-text-secondary">
                            {user?.instituteName || 'Your Institute'} Network Overview
                        </p>
                    </div>
                    <div className="mt-4 sm:mt-0">
                        <button
                            onClick={() => { fetchStats(); fetchClientCount(); }}
                            className="inline-flex items-center gap-2 px-4 py-2 bg-surface text-text-secondary rounded-lg border border-border-default hover:bg-gray-50 transition-colors"
                        >
                            <ArrowPathIcon className={`h-5 w-5 ${loading || loadingClients ? 'animate-spin' : ''}`} />
                            Refresh
                        </button>
                    </div>
                </div>

                {error && (
                    <div className="mb-8 p-4 bg-error/10 border border-error rounded-lg">
                        <p className="text-error flex items-center gap-2">
                            <ExclamationTriangleIcon className="h-5 w-5" />
                            {error}
                        </p>
                    </div>
                )}

                {/* Connection Status Card */}
                {stats && (
                    <div className="mb-8">
                        <Card className={`border-l-4 ${stats.isDeviceConnected ? 'border-l-success' : 'border-l-warning'}`}>
                            <div className="flex items-center justify-between">
                                <div>
                                    <h3 className="text-h3 text-text-primary mb-1">Your Device Status</h3>
                                    <p className="text-body-sm text-text-secondary">
                                        MAC Address: {user?.macAddress || 'Not Registered'}
                                    </p>
                                </div>
                                <div className={`px-4 py-2 rounded-full font-medium ${stats.isDeviceConnected
                                    ? 'bg-success/10 text-success'
                                    : 'bg-warning/10 text-warning-dark'
                                    }`}>
                                    {stats.isDeviceConnected ? 'Connected to Network' : 'Not Connected'}
                                </div>
                            </div>
                        </Card>
                    </div>
                )}

                {/* Network Stats Grid */}
                <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
                    {/* Network Status */}
                    <Card>
                        <div className="flex items-center gap-4">
                            <div className={`p-3 rounded-xl ${stats?.networkStatus === 'Secure' ? 'bg-success/10 text-success' : 'bg-error/10 text-error'
                                }`}>
                                <ShieldCheckIcon className="h-6 w-6" />
                            </div>
                            <div>
                                <p className="text-body-sm text-text-secondary">Network Status</p>
                                <p className="text-h2 text-text-primary mt-1">
                                    {stats?.networkStatus || 'Unknown'}
                                </p>
                            </div>
                        </div>
                    </Card>

                    {/* Active Network */}
                    <Card>
                        <div className="flex items-center gap-4">
                            <div className="p-3 bg-primary/10 text-primary rounded-xl">
                                <WifiIcon className="h-6 w-6" />
                            </div>
                            <div className="overflow-hidden">
                                <p className="text-body-sm text-text-secondary">Active Network</p>
                                <p className="text-h3 text-text-primary mt-1 truncate" title={stats?.activeSsid}>
                                    {stats?.activeSsid || 'None'}
                                </p>
                            </div>
                        </div>
                    </Card>

                    {/* Connected Clients */}
                    <Card>
                        <div className="flex items-center gap-4">
                            <div className="p-3 bg-blue-50 text-blue-600 rounded-xl">
                                <UsersIcon className="h-6 w-6" />
                            </div>
                            <div>
                                <p className="text-body-sm text-text-secondary">Connected Devices</p>
                                <p className="text-h2 text-text-primary mt-1">
                                    {loadingClients ? (
                                        <span className="inline-flex items-center gap-2">
                                            <ArrowPathIcon className="h-5 w-5 animate-spin text-blue-500" />
                                        </span>
                                    ) : clientCount !== null ? (
                                        clientCount
                                    ) : (
                                        '—'
                                    )}
                                </p>
                            </div>
                        </div>
                    </Card>

                    {/* AP Signal Strength */}
                    <Card>
                        <div className="flex items-center gap-4">
                            <div className="p-3 bg-purple-50 text-purple-600 rounded-xl">
                                <SignalIcon className="h-6 w-6" />
                            </div>
                            <div>
                                <p className="text-body-sm text-text-secondary">Signal Strength</p>
                                <p className="text-h2 text-text-primary mt-1">
                                    {stats?.apSignalStrength || 'N/A'}
                                </p>
                            </div>
                        </div>
                    </Card>
                </div>
            </main>
        </div>
    );
};
