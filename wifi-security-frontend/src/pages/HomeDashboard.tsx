import React from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useDetectionStatus } from '../hooks/useDetectionStatus';
import { Button, Card } from '../components/ui';
import {
    ShieldCheckIcon,
    HomeIcon,
    WifiIcon,
    ChartBarIcon,
    ExclamationTriangleIcon
} from '@heroicons/react/24/outline';

export const HomeDashboard: React.FC = () => {
    const navigate = useNavigate();
    const { user, logout } = useAuth();
    const { isUnderAttack, totalPackets, alerts, connected } = useDetectionStatus();

    const handleLogout = () => {
        logout();
        navigate('/login');
    };

    return (
        <div className="min-h-screen bg-background-primary">
            {/* Header */}
            <header className="border-b border-border-default bg-background-secondary">
                <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
                    <div className="flex h-16 items-center justify-between">
                        <div className="flex items-center gap-3">
                            <div className={`flex h-10 w-10 items-center justify-center rounded-card ${isUnderAttack ? 'bg-error animate-pulse' : 'bg-primary'}`}>
                                {isUnderAttack ? <ExclamationTriangleIcon className="h-6 w-6 text-white" /> : <ShieldCheckIcon className="h-6 w-6 text-white" />}
                            </div>
                            <span className="text-h4 font-display text-text-primary">
                                WiFi Shield
                            </span>
                        </div>

                        <div className="flex items-center gap-4">
                            <span className="text-body-sm text-text-secondary">
                                Welcome, <span className="text-text-primary font-medium">{user?.name}</span>
                            </span>
                            <Button variant="ghost" size="sm" onClick={handleLogout}>
                                Logout
                            </Button>
                        </div>
                    </div>
                </div>
            </header>

            {/* Main Content */}
            <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
                {/* Page Title */}
                <div className="mb-8">
                    <h1 className="text-h1 text-text-primary">Home Dashboard</h1>
                    <p className="text-body text-text-secondary mt-2">
                        {isUnderAttack ? '⚠️ Network Under Attack! Take action immediately.' : 'Protect your home network'}
                    </p>
                </div>

                {/* Network Info Card */}
                <Card className={`mb-8 ${isUnderAttack ? 'bg-red-50 border-red-200' : 'bg-gradient-card'}`}>
                    <div className="flex items-center justify-between">
                        <div>
                            <p className="text-caption text-text-muted uppercase tracking-wider">
                                Your Network
                            </p>
                            <h2 className="text-h2 text-text-primary mt-1">
                                Home Network
                            </h2>
                            <div className="flex items-center gap-2 mt-2">
                                <span className={`flex h-2 w-2 rounded-full ${isUnderAttack ? 'bg-red-600 animate-ping' : 'bg-success animate-pulse'}`} />
                                <span className={`text-body-sm ${isUnderAttack ? 'text-red-700 font-bold' : 'text-success'}`}>
                                    {isUnderAttack ? '⚠️ ATTACK DETECTED' : 'Protected'}
                                </span>
                                <span className={`text-xs ml-2 ${connected ? 'text-green-600' : 'text-orange-500'}`}>
                                    ({connected ? 'Live' : 'Connecting...'})
                                </span>
                            </div>
                        </div>
                        <div className={`flex h-16 w-16 items-center justify-center rounded-card ${isUnderAttack ? 'bg-red-100' : 'bg-success/10'}`}>
                            <WifiIcon className={`h-8 w-8 ${isUnderAttack ? 'text-red-600' : 'text-success'}`} />
                        </div>
                    </div>
                </Card>

                {/* Stats Grid */}
                <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3 mb-8">
                    <Card>
                        <div className="flex items-center justify-between">
                            <div>
                                <p className="text-caption text-text-muted">Packets Analyzed</p>
                                <p className="text-h2 text-text-primary mt-1">{totalPackets.toLocaleString()}</p>
                            </div>
                            <div className="flex h-12 w-12 items-center justify-center rounded-button bg-primary/10">
                                <ChartBarIcon className="h-6 w-6 text-primary" />
                            </div>
                        </div>
                    </Card>
                    <Card>
                        <div className="flex items-center justify-between">
                            <div>
                                <p className="text-caption text-text-muted">Threats Detected</p>
                                <p className="text-h2 text-text-primary mt-1">{alerts.length}</p>
                            </div>
                            <div className="flex h-12 w-12 items-center justify-center rounded-button bg-primary/10">
                                <ShieldCheckIcon className="h-6 w-6 text-primary" />
                            </div>
                        </div>
                    </Card>
                    <Card>
                        <div className="flex items-center justify-between">
                            <div>
                                <p className="text-caption text-text-muted">Network Health</p>
                                <p className={`text-h2 mt-1 ${isUnderAttack ? 'text-red-600 font-bold' : 'text-text-primary'}`}>{isUnderAttack ? 'Critical' : 'Good'}</p>
                            </div>
                            <div className="flex h-12 w-12 items-center justify-center rounded-button bg-primary/10">
                                <WifiIcon className="h-6 w-6 text-primary" />
                            </div>
                        </div>
                    </Card>
                </div>

                {/* Placeholder Content */}
                <Card>
                    <div className="text-center py-12">
                        <ChartBarIcon className="mx-auto h-12 w-12 text-text-muted" />
                        <h3 className="mt-4 text-h3 text-text-primary">
                            Home Security Dashboard Coming Soon
                        </h3>
                        <p className="mt-2 text-body text-text-secondary max-w-md mx-auto">
                            The full home security dashboard with device monitoring,
                            threat detection, and network analytics will be available in Module 2.
                        </p>
                    </div>
                </Card>
            </main>
        </div>
    );
};

export default HomeDashboard;
