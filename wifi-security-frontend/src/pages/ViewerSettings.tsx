import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { AppNavbar } from '../components/layout/AppNavbar';
import { Card, Button } from '../components/ui';
import api from '../services/api';
import {
    CheckCircleIcon,
    DevicePhoneMobileIcon,
    BellAlertIcon,
    WifiIcon,
    ArrowPathIcon,
    SignalIcon,
} from '@heroicons/react/24/outline';

interface ConnectedClient {
    macAddress: string;
    ipAddress: string;
    hostname: string;
    signalStrength: string;
    connectionTime: string;
}

export const ViewerSettings: React.FC = () => {
    const { user, updateProfile } = useAuth();

    // Selected MAC state
    const [selectedMac, setSelectedMac] = useState(user?.macAddress || '');
    const [manualMac, setManualMac] = useState('');
    const [savingMac, setSavingMac] = useState(false);
    const [macError, setMacError] = useState('');
    const [macSuccess, setMacSuccess] = useState(false);

    // Connected Clients state
    const [connectedClients, setConnectedClients] = useState<ConnectedClient[]>([]);
    const [loadingClients, setLoadingClients] = useState(false);
    const [clientsError, setClientsError] = useState('');

    // WiFi Adapter state removed

    // Phone number state removed

    // Alert preferences state
    const [emailAlerts, setEmailAlerts] = useState(user?.alertsEmail ?? true);
    const [savingAlerts, setSavingAlerts] = useState(false);

    const fetchClients = async () => {
        setLoadingClients(true);
        setClientsError('');
        try {
            const response = await api.get('/wifi/faculty/clients');
            setConnectedClients(response.data || []);
        } catch (err) {
            console.error('Failed to fetch assigned network clients', err);
            setClientsError('Could not load connected devices. Make sure your institute has a registered WiFi network.');
        } finally {
            setLoadingClients(false);
        }
    };

    useEffect(() => {
        fetchClients();
    }, []);

    const handleSaveMac = async (mac: string) => {
        setMacError('');
        setMacSuccess(false);
        const formattedMac = mac.trim().toUpperCase();
        setSelectedMac(formattedMac);

        setSavingMac(true);
        try {
            const response = await api.put('/users/mac-address', { macAddress: mac });
            if (response.status === 409) {
                const ownerName = response.data?.name || 'another user';
                setMacError(`This MAC address is already registered by "${ownerName}". Each device can only be registered to one user.`);
                setSavingMac(false);
                return;
            }
            updateProfile(response.data);
            setMacSuccess(true);
            setTimeout(() => setMacSuccess(false), 4000);
        } catch (error: any) {
            console.error('MAC save error:', error);
            if (error.response?.status === 409) {
                const ownerName = error.response?.data?.name || 'another user';
                setMacError(`This MAC address is already registered by "${ownerName}". Each device can only be registered to one user.`);
            } else {
                setMacError(error.response?.data?.message || error.response?.data?.error || 'Failed to update MAC address. Please try again.');
            }
        } finally {
            setSavingMac(false);
        }
    };



    const handleToggleAlerts = async (type: 'email', value: boolean) => {
        if (type === 'email') setEmailAlerts(value);
        setSavingAlerts(true);
        try {
            await api.put('/users/me/alert-preferences', {
                alertsEmail: value,
                alertsSms: false,
            });
        } catch (error: any) {
            console.error('Alert preference save error:', error);
            // revert
            if (type === 'email') setEmailAlerts(!value);
        } finally {
            setSavingAlerts(false);
        }
    };

    return (
        <div className="min-h-screen bg-background-primary">
            <AppNavbar />
            <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
                <div className="mb-6">
                    <h1 className="text-h1 text-text-primary">Settings</h1>
                    <p className="text-body text-text-secondary mt-2">
                        Manage your account, device preferences, and alert notifications.
                    </p>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                    {/* Device Registration - Takes 2 columns */}
                    <div className="lg:col-span-2">
                        <Card>
                            <div className="flex items-center justify-between mb-4">
                                <div className="flex items-center gap-3">
                                    <DevicePhoneMobileIcon className="h-6 w-6 text-primary" />
                                    <h3 className="text-h3 text-text-primary">Device Registration</h3>
                                </div>
                                <button
                                    onClick={fetchClients}
                                    disabled={loadingClients}
                                    className="inline-flex items-center gap-1.5 px-3 py-1.5 text-sm text-text-secondary border border-border-default rounded-lg hover:bg-gray-50 transition-colors"
                                >
                                    <ArrowPathIcon className={`h-4 w-4 ${loadingClients ? 'animate-spin' : ''}`} />
                                    Refresh
                                </button>
                            </div>
                            <p className="text-body-sm text-text-secondary mb-4">
                                Select your device from the connected clients on your institute's Wi-Fi network, or enter the MAC address manually.
                            </p>

                            {/* Manual MAC Entry */}
                            <div className="mb-6 bg-surface border border-border-default rounded-lg p-4">
                                <h4 className="text-sm font-medium text-text-primary mb-2">Register Manually</h4>
                                <div className="flex gap-2">
                                    <input
                                        type="text"
                                        value={manualMac}
                                        onChange={(e) => setManualMac(e.target.value.toUpperCase())}
                                        placeholder="e.g. AA:BB:CC:DD:EE:FF"
                                        className="flex-1 px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-primary focus:border-primary font-mono uppercase"
                                        maxLength={17}
                                    />
                                    <Button
                                        onClick={() => handleSaveMac(manualMac)}
                                        isLoading={savingMac && selectedMac === manualMac.trim().toUpperCase()}
                                        className="!px-4 !py-2 !text-sm"
                                        disabled={!/^([0-9A-FA-F]{2}[:-]){5}([0-9A-FA-F]{2})$/.test(manualMac)}
                                    >
                                        Save MAC
                                    </Button>
                                </div>
                                <p className="text-xs text-text-secondary mt-2">
                                    Enter your device's MAC address directly if it doesn't appear in the network scan below.
                                </p>
                            </div>

                            {/* Success Banner */}
                            {macSuccess && (
                                <div className="mb-4 p-3 bg-green-50 border border-green-200 rounded-lg flex items-center gap-2">
                                    <CheckCircleIcon className="h-5 w-5 text-green-600" />
                                    <span className="text-sm font-medium text-green-800">
                                        Device MAC address saved successfully!
                                    </span>
                                </div>
                            )}

                            {/* Error Banner */}
                            {macError && (
                                <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-lg">
                                    <span className="text-sm font-medium text-red-800">{macError}</span>
                                </div>
                            )}

                            {clientsError && (
                                <div className="mb-4 p-3 bg-yellow-50 border border-yellow-200 rounded-lg">
                                    <span className="text-sm font-medium text-yellow-800">{clientsError}</span>
                                </div>
                            )}

                            {/* Connected Clients Table */}
                            {loadingClients ? (
                                <div className="flex flex-col items-center justify-center py-12">
                                    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary mb-3"></div>
                                    <p className="text-sm text-text-secondary">Scanning for connected devices...</p>
                                </div>
                            ) : connectedClients.length === 0 ? (
                                <div className="flex flex-col items-center justify-center py-12 text-center">
                                    <WifiIcon className="h-12 w-12 text-gray-300 mb-3" />
                                    <p className="text-text-secondary font-medium">No connected devices found</p>
                                    <p className="text-sm text-text-secondary mt-1">
                                        Make sure you're connected to your institute's Wi-Fi network.
                                    </p>
                                </div>
                            ) : (
                                <div className="overflow-hidden rounded-lg border border-gray-200">
                                    {/* Table Header */}
                                    <div className="grid grid-cols-12 gap-2 bg-gray-800 text-white text-xs font-bold uppercase tracking-wider px-4 py-3">
                                        <div className="col-span-4">Device</div>
                                        <div className="col-span-3">MAC Address</div>
                                        <div className="col-span-2">IP Address</div>
                                        <div className="col-span-1">Signal</div>
                                        <div className="col-span-2 text-right">Action</div>
                                    </div>

                                    {/* Table Body */}
                                    <div className="divide-y divide-gray-100">
                                        {connectedClients.map((client, idx) => {
                                            const isSelected = selectedMac === client.macAddress;
                                            const isCurrentDevice = user?.macAddress === client.macAddress;
                                            return (
                                                <div
                                                    key={idx}
                                                    className={`grid grid-cols-12 gap-2 items-center px-4 py-3 transition-colors ${isCurrentDevice
                                                        ? 'bg-green-50 border-l-4 border-l-green-500'
                                                        : isSelected
                                                            ? 'bg-blue-50 border-l-4 border-l-blue-500'
                                                            : 'hover:bg-gray-50'
                                                        }`}
                                                >
                                                    {/* Device Name */}
                                                    <div className="col-span-4 flex items-center gap-2">
                                                        <div className={`w-2 h-2 rounded-full ${isCurrentDevice ? 'bg-green-500' : 'bg-blue-400'}`}></div>
                                                        <span className="text-sm font-medium text-gray-800 truncate">
                                                            {client.hostname && client.hostname !== 'Unknown'
                                                                ? client.hostname
                                                                : 'Unknown Device'}
                                                        </span>
                                                    </div>

                                                    {/* MAC Address */}
                                                    <div className="col-span-3">
                                                        <code className="text-xs bg-gray-100 text-blue-700 px-2 py-1 rounded font-mono">
                                                            {client.macAddress}
                                                        </code>
                                                    </div>

                                                    {/* IP Address */}
                                                    <div className="col-span-2 text-sm text-gray-600">
                                                        {client.ipAddress || '—'}
                                                    </div>

                                                    {/* Signal */}
                                                    <div className="col-span-1 flex items-center gap-1">
                                                        <SignalIcon className="h-3.5 w-3.5 text-gray-400" />
                                                        <span className="text-xs text-gray-500">
                                                            {client.signalStrength || 'N/A'}
                                                        </span>
                                                    </div>

                                                    {/* Action Button */}
                                                    <div className="col-span-2 text-right">
                                                        {isCurrentDevice ? (
                                                            <span className="inline-flex items-center gap-1 px-3 py-1.5 text-xs font-bold text-green-700 bg-green-100 rounded-full">
                                                                <CheckCircleIcon className="h-3.5 w-3.5" />
                                                                My Device
                                                            </span>
                                                        ) : (
                                                            <Button
                                                                onClick={() => handleSaveMac(client.macAddress)}
                                                                isLoading={savingMac && selectedMac === client.macAddress}
                                                                className="!px-3 !py-1.5 !text-xs"
                                                            >
                                                                Register
                                                            </Button>
                                                        )}
                                                    </div>
                                                </div>
                                            );
                                        })}
                                    </div>
                                </div>
                            )}
                        </Card>
                    </div>

                    {/* Right Column - Settings */}
                    <div className="space-y-6">

                        {/* Notifications & Alerts */}
                        <Card>
                            <div className="flex items-center gap-3 mb-4">
                                <BellAlertIcon className="h-6 w-6 text-primary" />
                                <h3 className="text-h3 text-text-primary">Alert Notifications</h3>
                            </div>


                            <div className="space-y-3">
                                {/* Email Alerts Toggle */}
                                <div className="flex items-center justify-between p-3 border rounded-lg bg-surface">
                                    <div>
                                        <h4 className="font-medium text-text-primary text-sm">Email Alerts</h4>
                                        <p className="text-xs text-text-secondary">
                                            Receive email when a threat is detected.
                                        </p>
                                    </div>
                                    <label className="relative inline-flex items-center cursor-pointer">
                                        <input
                                            type="checkbox"
                                            className="sr-only peer"
                                            checked={emailAlerts}
                                            onChange={() => handleToggleAlerts('email', !emailAlerts)}
                                        />
                                        <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary"></div>
                                    </label>
                                </div>

                            </div>
                        </Card>

                        {/* Current Registration Info */}
                        <Card>
                            <h4 className="font-medium text-text-primary mb-3">Current Registration</h4>
                            <div className="space-y-2 text-sm">
                                <div className="flex justify-between">
                                    <span className="text-text-secondary">Registered MAC:</span>
                                    <code className="text-xs bg-gray-100 text-gray-700 px-2 py-0.5 rounded font-mono">
                                        {user?.macAddress || 'None'}
                                    </code>
                                </div>

                                <div className="flex justify-between">
                                    <span className="text-text-secondary">Institute:</span>
                                    <span className="text-text-primary font-medium">
                                        {user?.instituteName || 'N/A'}
                                    </span>
                                </div>
                            </div>
                        </Card>
                    </div>
                </div>
            </main>
        </div>
    );
};
