import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { AppNavbar } from '../components/layout/AppNavbar';
import { Button } from '../components/ui';
import api from '../services/api';
import {
    CheckCircleIcon,
    BellAlertIcon,
    WifiIcon,
} from '@heroicons/react/24/outline';

export const AdminSettings: React.FC = () => {
    const { user } = useAuth();

    // WiFi Adapter state removed


    // Phone number state removed


    // Alert preferences state
    const [emailAlerts, setEmailAlerts] = useState(user?.alertsEmail ?? true);



    const handleToggleAlerts = async (type: 'email', value: boolean) => {
        if (type === 'email') setEmailAlerts(value);
        try {
            await api.put('/users/me/alert-preferences', {
                alertsEmail: value,
                alertsSms: false,
            });
        } catch (error: any) {
            console.error('Alert preference save error:', error);
            if (type === 'email') setEmailAlerts(!value);
        }
    };

    return (
        <div className="min-h-screen bg-gray-50">
            <AppNavbar />
            <main className="mx-auto max-w-3xl px-4 py-8 sm:px-6 lg:px-8">
                <div className="mb-6">
                    <h1 className="text-2xl font-bold text-gray-900">Settings</h1>
                </div>

                <div className="space-y-6">

                    {/* Alert Notifications */}
                    <div className="bg-white border border-gray-200 rounded-xl p-6">
                        <div className="flex items-center gap-3 mb-4">
                            <BellAlertIcon className="h-6 w-6 text-blue-600" />
                            <h3 className="text-lg font-bold text-gray-900">Alert Notifications</h3>
                        </div>



                        <div className="space-y-3">
                            {/* Email Toggle */}
                            <div className="flex items-center justify-between p-3 border rounded-lg">
                                <div>
                                    <h4 className="font-medium text-gray-900 text-sm">Email Alerts</h4>
                                    <p className="text-xs text-gray-500">Receive email when a threat is detected</p>
                                </div>
                                <label className="relative inline-flex items-center cursor-pointer">
                                    <input type="checkbox" className="sr-only peer" checked={emailAlerts} onChange={() => handleToggleAlerts('email', !emailAlerts)} />
                                    <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
                                </label>
                            </div>
                        </div>
                    </div>
                </div>
            </main>
        </div>
    );
};

export default AdminSettings;
