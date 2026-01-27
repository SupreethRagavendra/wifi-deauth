import React from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { Button, Card } from '../components/ui';
import {
    ShieldCheckIcon,
    HomeIcon,
    WifiIcon,
    ChartBarIcon,
} from '@heroicons/react/24/outline';

export const HomeDashboard: React.FC = () => {
    const navigate = useNavigate();
    const { user, logout } = useAuth();

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
                            <div className="flex h-10 w-10 items-center justify-center rounded-card bg-primary">
                                <ShieldCheckIcon className="h-6 w-6 text-white" />
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
                        Protect your home network
                    </p>
                </div>

                {/* Network Info Card */}
                <Card className="mb-8 bg-gradient-card">
                    <div className="flex items-center justify-between">
                        <div>
                            <p className="text-caption text-text-muted uppercase tracking-wider">
                                Your Network
                            </p>
                            <h2 className="text-h2 text-text-primary mt-1">
                                Home Network
                            </h2>
                            <div className="flex items-center gap-2 mt-2">
                                <span className="flex h-2 w-2 rounded-full bg-success animate-pulse" />
                                <span className="text-body-sm text-success">Protected</span>
                            </div>
                        </div>
                        <div className="flex h-16 w-16 items-center justify-center rounded-card bg-success/10">
                            <WifiIcon className="h-8 w-8 text-success" />
                        </div>
                    </div>
                </Card>

                {/* Stats Grid */}
                <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3 mb-8">
                    {[
                        { label: 'Connected Devices', value: '—', icon: HomeIcon },
                        { label: 'Threats Blocked', value: '—', icon: ShieldCheckIcon },
                        { label: 'Network Health', value: 'Good', icon: WifiIcon },
                    ].map((stat) => (
                        <Card key={stat.label}>
                            <div className="flex items-center justify-between">
                                <div>
                                    <p className="text-caption text-text-muted">{stat.label}</p>
                                    <p className="text-h2 text-text-primary mt-1">{stat.value}</p>
                                </div>
                                <div className="flex h-12 w-12 items-center justify-center rounded-button bg-primary/10">
                                    <stat.icon className="h-6 w-6 text-primary" />
                                </div>
                            </div>
                        </Card>
                    ))}
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
