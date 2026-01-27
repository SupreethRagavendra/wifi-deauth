import React from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { Button, Card } from '../components/ui';
import {
    ShieldCheckIcon,
    UserGroupIcon,
    ChartBarIcon,
    Cog6ToothIcon,
} from '@heroicons/react/24/outline';

export const AdminDashboard: React.FC = () => {
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
                    <h1 className="text-h1 text-text-primary">Admin Dashboard</h1>
                    <p className="text-body text-text-secondary mt-2">
                        Manage your organization's network security
                    </p>
                </div>

                {/* Institute Info Card */}
                {user?.instituteName && (
                    <Card className="mb-8 bg-gradient-card">
                        <div className="flex items-center justify-between">
                            <div>
                                <p className="text-caption text-text-muted uppercase tracking-wider">
                                    Institution
                                </p>
                                <h2 className="text-h2 text-text-primary mt-1">
                                    {user.instituteName}
                                </h2>
                                {user.instituteCode && (
                                    <p className="text-body-sm text-text-secondary mt-2">
                                        Institute Code: <span className="font-mono text-primary">{user.instituteCode}</span>
                                    </p>
                                )}
                            </div>
                            <div className="flex h-16 w-16 items-center justify-center rounded-card bg-primary/10">
                                <UserGroupIcon className="h-8 w-8 text-primary" />
                            </div>
                        </div>
                    </Card>
                )}

                {/* Stats Grid */}
                <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-4 mb-8">
                    {[
                        { label: 'Total Devices', value: '—', icon: ShieldCheckIcon },
                        { label: 'Active Users', value: '—', icon: UserGroupIcon },
                        { label: 'Alerts Today', value: '—', icon: ChartBarIcon },
                        { label: 'System Status', value: 'Online', icon: Cog6ToothIcon },
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
                            Dashboard Coming Soon
                        </h3>
                        <p className="mt-2 text-body text-text-secondary max-w-md mx-auto">
                            The full dashboard with device monitoring, alerts, and analytics
                            will be available in Module 2.
                        </p>
                    </div>
                </Card>
            </main>
        </div>
    );
};

export default AdminDashboard;
