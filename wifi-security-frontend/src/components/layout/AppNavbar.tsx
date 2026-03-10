import React from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { ShieldCheckIcon, ExclamationTriangleIcon } from '@heroicons/react/24/outline';

interface AppNavbarProps {
    /** Show attack pulse on logo when true */
    isUnderAttack?: boolean;
}

export const AppNavbar: React.FC<AppNavbarProps> = ({ isUnderAttack = false }) => {
    const navigate = useNavigate();
    const location = useLocation();
    const { user, logout } = useAuth();

    const handleLogout = () => {
        logout();
        navigate('/login');
    };

    const isActive = (path: string) => location.pathname === path;

    const navLinks: { label: string; path: string; color: string }[] = [];

    if (user?.role === 'ADMIN') {
        navLinks.push(
            { label: 'Dashboard', path: '/admin/dashboard', color: 'blue' },
            { label: 'Detection Monitor', path: '/detection-monitor', color: 'blue' },
            { label: 'Prevention', path: '/prevention', color: 'blue' },
            { label: 'Settings', path: '/admin/settings', color: 'blue' },
        );
    } else if (user?.role === 'VIEWER') {
        navLinks.push(
            { label: 'Dashboard', path: '/viewer/dashboard', color: 'blue' },
            { label: 'Detection', path: '/viewer/detection', color: 'blue' },
            { label: 'Settings', path: '/viewer/settings', color: 'blue' },
        );
    } else if (user?.role === 'HOME_USER') {
        navLinks.push(
            { label: 'Dashboard', path: '/home/dashboard', color: 'blue' },
        );
    }

    return (
        <header className="bg-white border-b border-gray-200 sticky top-0 z-30">
            <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
                <div className="flex h-16 items-center justify-between">
                    {/* Logo */}
                    <div className="flex items-center gap-3">
                        <div
                            className={`flex h-8 w-8 items-center justify-center rounded-lg transition-colors ${isUnderAttack ? 'bg-red-600 animate-pulse' : 'bg-blue-600'
                                }`}
                        >
                            {isUnderAttack
                                ? <ExclamationTriangleIcon className="h-5 w-5 text-white" />
                                : <ShieldCheckIcon className="h-5 w-5 text-white" />}
                        </div>
                        <span className="text-xl font-bold text-gray-900 font-mono uppercase tracking-[0.1em]">
                            WiFi Shield
                        </span>
                    </div>

                    {/* Nav Links + User */}
                    <div className="flex items-center gap-1">
                        <span className="text-[11px] text-gray-500 font-mono tracking-[0.1em] mr-3">
                            Welcome, <span className="font-semibold text-gray-900">{user?.name}</span>
                        </span>

                        {navLinks.map(({ label, path, color }) => {
                            const active = isActive(path);
                            const colorClasses =
                                color === 'red'
                                    ? active
                                        ? 'text-red-700 border-b-2 border-red-600 pb-0.5'
                                        : 'text-red-600 hover:text-red-800'
                                    : active
                                        ? 'text-blue-700 border-b-2 border-blue-600 pb-0.5'
                                        : 'text-blue-600 hover:text-blue-800';

                            return (
                                <button
                                    key={path}
                                    onClick={() => navigate(path)}
                                    className={`px-3 py-1 text-[11px] font-semibold font-mono uppercase tracking-[0.2em] transition-colors ${colorClasses}`}
                                >
                                    {label}
                                </button>
                            );
                        })}

                        <button
                            onClick={handleLogout}
                            className="px-3 py-1 text-[11px] font-semibold text-gray-500 hover:text-gray-900 font-mono uppercase tracking-[0.2em] transition-colors"
                        >
                            Logout
                        </button>
                    </div>
                </div>
            </div>
        </header>
    );
};

export default AppNavbar;
