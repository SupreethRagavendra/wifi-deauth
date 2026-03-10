import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { Button, Input, Select, Alert } from '../components/ui';
import { wifiService, detectionService } from '../services/api';
import { useDetectionStatus } from '../hooks/useDetectionStatus';
import { useLiveStatus } from '../hooks/useLiveStatus';
import { WiFiNetwork, SecurityType, WiFiNetworkRequest, WiFiScanResult, ConnectedClient } from '../types';
import { AppNavbar } from '../components/layout/AppNavbar';
import {
    ShieldCheckIcon,
    UserGroupIcon,
    ChartBarIcon,
    CheckCircleIcon,
    PlusIcon,
    WifiIcon,
    TrashIcon,
    ArrowPathIcon,
    SignalIcon,
    ChevronRightIcon,
    ComputerDesktopIcon,
    DevicePhoneMobileIcon,
} from '@heroicons/react/24/outline';
import { DetectionFeed } from '../components/DetectionFeed';

const SECURITY_OPTIONS = [
    { value: 'WPA2', label: 'WPA2' },
    { value: 'WPA', label: 'WPA' },
    { value: 'WEP', label: 'WEP' },
    { value: 'OPEN', label: 'OPEN' },
    { value: 'WPA3', label: 'WPA3' },
    { value: 'WPA2_ENTERPRISE', label: 'WPA2 Enterprise' },
];


export const AdminDashboard: React.FC = () => {
    const navigate = useNavigate();
    const { user } = useAuth();
    const { isUnderAttack, attackDetails, totalPackets, connected } = useDetectionStatus();
    const { systemStatus, activeThreats, threatsLastHour, underAttack } = useLiveStatus();

    const [networks, setNetworks] = useState<WiFiNetwork[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [showAddForm, setShowAddForm] = useState(false);

    // Scan State
    const [isScanning, setIsScanning] = useState(false);
    const [scanResults, setScanResults] = useState<WiFiScanResult[]>([]);
    const [showScanResults, setShowScanResults] = useState(false);

    // Expandable row state
    const [expandedNetwork, setExpandedNetwork] = useState<string | null>(null);

    // Connected clients state - will be populated by API when backend is active
    const [networkClients, setNetworkClients] = useState<Record<string, ConnectedClient[]>>({});
    const [loadingClients, setLoadingClients] = useState<string | null>(null);
    const [clientErrors, setClientErrors] = useState<Record<string, string>>({});

    // Detection feed refresh trigger
    const [feedRefreshTrigger, setFeedRefreshTrigger] = useState(0);
    const [clearing, setClearing] = useState(false);
    const [clearSuccess, setClearSuccess] = useState(false);



    const getClientsForNetwork = (networkId: string): ConnectedClient[] => {
        return networkClients[networkId] || [];
    };

    // Fetch connected clients when a network is expanded
    const handleExpandNetwork = async (networkId: string) => {
        if (expandedNetwork === networkId) {
            setExpandedNetwork(null);
            return;
        }
        setExpandedNetwork(networkId);

        if (!networkClients[networkId]) {
            setLoadingClients(networkId);
            setClientErrors(prev => {
                const newErrors = { ...prev };
                delete newErrors[networkId];
                return newErrors;
            });

            try {
                const response = await wifiService.getConnectedClients(networkId);
                if (response.success && response.data) {
                    setNetworkClients(prev => ({ ...prev, [networkId]: response.data! }));
                } else {
                    setClientErrors(prev => ({ ...prev, [networkId]: response.error || 'Failed to load clients' }));
                }
            } catch (err) {
                setClientErrors(prev => ({ ...prev, [networkId]: 'Failed to connect to backend' }));
            } finally {
                setLoadingClients(null);
            }
        }
    };

    // Form State
    const [formData, setFormData] = useState<WiFiNetworkRequest>({
        ssid: '',
        bssid: '',
        channel: 1,
        securityType: 'WPA2',
        location: '',
    });
    const [formError, setFormError] = useState<string | null>(null);
    const [submitting, setSubmitting] = useState(false);

    useEffect(() => {
        fetchNetworks();
    }, []);

    const fetchNetworks = async () => {
        setLoading(true);
        const response = await wifiService.getNetworks();
        if (response.success && response.data) {
            setNetworks(response.data);
            setError(null);
        } else {
            setError(response.error || 'Failed to fetch networks');
        }
        setLoading(false);
    };

    const handleDelete = async (id: string) => {
        if (window.confirm('Are you sure you want to delete this network?')) {
            const response = await wifiService.deleteNetwork(id);
            if (response.success) {
                fetchNetworks();
            } else {
                setError(response.error || 'Failed to delete network');
            }
        }
    };

    const handleAddNetwork = async (e: React.FormEvent) => {
        e.preventDefault();
        setSubmitting(true);
        setFormError(null);

        const response = await wifiService.addNetwork(formData);

        if (response.success) {
            setShowAddForm(false);
            setFormData({
                ssid: '',
                bssid: '',
                channel: 1,
                securityType: 'WPA2',
                location: '',
            });
            fetchNetworks();
        } else {
            setFormError(response.error || 'Failed to add network');
        }
        setSubmitting(false);
    };

    const handleScan = async () => {
        setIsScanning(true);
        setFormError(null);

        // First attempt
        let response = await wifiService.scanNetworks();

        // Auto-retry once if empty (interface may not be ready on first call)
        if (response.success && response.data && response.data.length === 0) {
            await new Promise(res => setTimeout(res, 1500));
            response = await wifiService.scanNetworks();
        }

        if (response.success && response.data) {
            setScanResults(response.data);
            if (response.data.length > 0) {
                setShowScanResults(true);
            } else {
                setFormError('No networks detected. The wireless interface may not be active. Try scanning again or add a network manually using its SSID and BSSID.');
            }
        } else {
            setFormError(response.error || 'Scan failed. Please try again.');
        }
        setIsScanning(false);
    };

    const selectScanResult = (result: WiFiScanResult) => {
        // Auto-fill form
        setFormData({
            ssid: result.ssid,
            bssid: result.bssid,
            channel: result.channel,
            securityType: (result.securityType as SecurityType) || 'WPA2', // Fallback
            location: '',
        });
        setShowAddForm(true);
        setShowScanResults(false);
    };



    return (
        <div className="min-h-screen bg-gray-50">
            <AppNavbar isUnderAttack={isUnderAttack} />

            {/* Main Content */}
            <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
                {/* Title */}
                <div className="mb-8">
                    <h1 className="text-3xl font-bold text-gray-900">Admin Dashboard</h1>
                    <p className="mt-1 text-gray-500">Real-time network security monitoring</p>
                </div>

                {/* Institute Info Card */}
                {user?.instituteName && (
                    <div className="mb-8 rounded-xl bg-white p-6 shadow-sm border border-gray-100 flex items-center justify-between">
                        <div>
                            <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-gray-400 font-mono">
                                INSTITUTION
                            </p>
                            <h2 className="mt-1 text-2xl font-bold text-gray-900">
                                {user.instituteName}
                            </h2>
                            {user.instituteCode && (
                                <p className="mt-2 text-sm text-gray-500">
                                    Institute Code: <span className="font-mono font-medium text-blue-600">{user.instituteCode}</span>
                                </p>
                            )}
                        </div>
                        <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-blue-50">
                            <UserGroupIcon className="h-6 w-6 text-blue-600" />
                        </div>
                    </div>
                )}

                {/* Stats Grid */}
                <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-4 mb-10">
                    <div className="rounded-xl bg-white p-6 shadow-sm border border-gray-100 flex items-center justify-between">
                        <div>
                            <p className="text-[11px] font-semibold text-gray-500 font-mono uppercase tracking-[0.2em]">Registered Networks</p>
                            <p className="mt-2 text-3xl font-bold text-gray-900">{networks.length}</p>
                        </div>
                        <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-blue-50">
                            <WifiIcon className="h-5 w-5 text-blue-600" />
                        </div>
                    </div>

                    <div className="rounded-xl bg-white p-6 shadow-sm border border-gray-100 flex items-center justify-between">
                        <div>
                            <p className="text-[11px] font-semibold text-gray-500 font-mono uppercase tracking-[0.2em]">Total Packets Analyzed</p>
                            <p className="mt-2 text-3xl font-bold text-gray-900">{totalPackets.toLocaleString()}</p>
                        </div>
                        <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-indigo-50">
                            <ChartBarIcon className="h-5 w-5 text-indigo-600" />
                        </div>
                    </div>

                    <div className="rounded-xl bg-white p-6 shadow-sm border border-gray-100 flex items-center justify-between">
                        <div>
                            <p className="text-[11px] font-semibold text-gray-500 font-mono uppercase tracking-[0.2em]">Attacks Detected (1hr)</p>
                            <p className="mt-2 text-3xl font-bold text-red-600">{threatsLastHour}</p>
                        </div>
                        <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-violet-50">
                            <ShieldCheckIcon className="h-5 w-5 text-red-600" />
                        </div>
                    </div>

                    <div className="rounded-xl bg-white p-6 shadow-sm border border-gray-100 flex items-center justify-between">
                        <div>
                            <p className="text-[11px] font-semibold text-gray-500 font-mono uppercase tracking-[0.2em]">Connection</p>
                            <p className={`mt-2 text-2xl font-bold ${connected ? 'text-green-500' : 'text-orange-500'}`}>
                                {connected ? 'Online' : 'Reconnecting...'}
                            </p>
                        </div>
                        <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-green-50">
                            <CheckCircleIcon className={`h-5 w-5 ${connected ? 'text-green-600' : 'text-orange-500'}`} />
                        </div>
                    </div>
                </div>

                {error && (
                    <div className="mb-6">
                        <Alert variant="error" title="Error">{error}</Alert>
                    </div>
                )}

                {/* Registered Networks Section */}
                <div className="mb-8">
                    <div className="flex items-center justify-between mb-6">
                        <h3 className="text-xl font-bold text-gray-900">Registered WiFi Networks</h3>
                        <Button onClick={() => setShowAddForm(!showAddForm)}>
                            <PlusIcon className="mr-2 h-4 w-4" />
                            REGISTER NEW WIFI
                        </Button>
                    </div>

                    {/* Add Network Modal */}
                    {showAddForm && (
                        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4 overflow-y-auto">
                            <div className="w-full max-w-lg bg-white rounded-2xl shadow-2xl ring-1 ring-gray-200 transform transition-all scale-100 opacity-100">
                                {/* Modal Header */}
                                <div className="border-b border-gray-100 px-6 py-4 flex items-center justify-between bg-gray-50/80 rounded-t-2xl">
                                    <div className="flex items-center gap-2">
                                        <div className="p-1.5 bg-blue-100 rounded-lg">
                                            <WifiIcon className="h-5 w-5 text-blue-600" />
                                        </div>
                                        <h4 className="text-lg font-bold text-gray-900">Add New Network</h4>
                                    </div>
                                    <button
                                        type="button"
                                        onClick={() => setShowAddForm(false)}
                                        className="text-gray-400 hover:text-gray-600 transition-colors p-1 hover:bg-gray-100 rounded-full"
                                    >
                                        <span className="sr-only">Close</span>
                                        <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" strokeWidth="1.5" stroke="currentColor">
                                            <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                                        </svg>
                                    </button>
                                </div>

                                {/* Modal Body */}
                                <div className="p-6">
                                    {formError && (
                                        <div className="mb-4">
                                            <Alert variant="error" title="Error">{formError}</Alert>
                                        </div>
                                    )}

                                    {/* Scan Action */}
                                    <div className="mb-6 bg-blue-50/50 rounded-xl p-4 border border-blue-100 flex items-center justify-between">
                                        <div className="text-sm text-blue-700">
                                            <span className="font-semibold block text-blue-900">Auto-Detect Networks</span>
                                            Scan nearby WiFi to auto-fill details.
                                        </div>
                                        <Button
                                            variant="secondary"
                                            size="sm"
                                            onClick={handleScan}
                                            isLoading={isScanning}
                                            className="whitespace-nowrap bg-white text-blue-600 border-blue-200 hover:bg-blue-50 shadow-sm"
                                        >
                                            <ArrowPathIcon className={`mr-2 h-4 w-4 ${isScanning ? 'animate-spin' : ''}`} />
                                            Scan Now
                                        </Button>
                                    </div>

                                    {/* Scan Results Dropdown */}
                                    {showScanResults && scanResults.length > 0 && (
                                        <div className="mb-6 border rounded-xl overflow-hidden border-gray-200 shadow-lg animate-fade-in">
                                            <div className="bg-gray-50 px-4 py-2 border-b border-gray-200 font-semibold text-[11px] uppercase tracking-[0.2em] text-gray-500 font-mono flex justify-between items-center">
                                                <span>Detected Networks ({scanResults.length})</span>
                                                <button onClick={() => setShowScanResults(false)} className="text-blue-600 hover:text-blue-800">Close</button>
                                            </div>
                                            <div className="max-h-[200px] overflow-y-auto bg-white divide-y divide-gray-100">
                                                {scanResults.map((result, idx) => (
                                                    <button
                                                        key={`${result.bssid}-${idx}`}
                                                        type="button"
                                                        onClick={() => selectScanResult(result)}
                                                        className="w-full text-left px-4 py-3 hover:bg-blue-50 transition-colors group"
                                                    >
                                                        <div className="flex justify-between items-center">
                                                            <div>
                                                                <div className="font-semibold text-gray-900 group-hover:text-blue-700">{result.ssid || '<Hidden SSID>'}</div>
                                                                <div className="text-xs text-gray-500 font-mono mt-0.5">{result.bssid}</div>
                                                            </div>
                                                            <div className="text-right">
                                                                <div className="flex items-center gap-1 justify-end text-xs font-medium text-gray-700 bg-gray-100 px-2 py-0.5 rounded-full mb-1">
                                                                    <SignalIcon className="h-3 w-3" />
                                                                    {result.signalStrength}%
                                                                </div>
                                                                <div className="text-xs text-gray-400">CH {result.channel} • {result.securityType || 'OPEN'}</div>
                                                            </div>
                                                        </div>
                                                    </button>
                                                ))}
                                            </div>
                                        </div>
                                    )}

                                    <form onSubmit={handleAddNetwork}>
                                        <div className="space-y-4">
                                            <div>
                                                <Input
                                                    label="SSID"
                                                    placeholder="Network Name"
                                                    value={formData.ssid}
                                                    onChange={(e) => setFormData({ ...formData, ssid: e.target.value })}
                                                    required
                                                    className="bg-white"
                                                />
                                            </div>
                                            <div>
                                                <Input
                                                    label="BSSID (MAC Address)"
                                                    placeholder="00:11:22:33:44:55"
                                                    value={formData.bssid}
                                                    onChange={(e) => setFormData({ ...formData, bssid: e.target.value })}
                                                    required
                                                    className="font-mono bg-white"
                                                />
                                            </div>
                                            <div className="grid grid-cols-2 gap-4">
                                                <Input
                                                    label="Channel"
                                                    type="number"
                                                    placeholder="e.g. 6"
                                                    value={formData.channel}
                                                    onChange={(e) => setFormData({ ...formData, channel: parseInt(e.target.value) || 0 })}
                                                    className="bg-white"
                                                />
                                                <Select
                                                    label="Security"
                                                    options={SECURITY_OPTIONS}
                                                    value={formData.securityType}
                                                    onChange={(e) => setFormData({ ...formData, securityType: e.target.value as SecurityType })}
                                                />
                                            </div>
                                            <div>
                                                <Input
                                                    label="Location"
                                                    placeholder="e.g. Main Office, Floor 1"
                                                    value={formData.location || ''}
                                                    onChange={(e) => setFormData({ ...formData, location: e.target.value })}
                                                    className="bg-white"
                                                />
                                            </div>
                                        </div>

                                        <div className="mt-8 flex justify-end gap-3">
                                            <Button
                                                type="button"
                                                variant="ghost"
                                                onClick={() => setShowAddForm(false)}
                                            >
                                                Cancel
                                            </Button>
                                            <Button type="submit" isLoading={submitting}>
                                                Add Network
                                            </Button>
                                        </div>
                                    </form>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Networks Table */}
                    <div className="rounded-xl border border-gray-200 bg-white overflow-hidden shadow-sm">
                        <div className="overflow-x-auto">
                            <table className="min-w-full divide-y divide-gray-200">
                                <thead className="bg-gray-50">
                                    <tr>
                                        <th scope="col" className="w-10 px-3 py-3"></th>
                                        <th scope="col" className="px-6 py-3 text-left text-[11px] font-semibold text-gray-500 uppercase tracking-[0.2em] font-mono">SSID</th>
                                        <th scope="col" className="px-6 py-3 text-left text-[11px] font-semibold text-gray-500 uppercase tracking-[0.2em] font-mono">BSSID</th>
                                        <th scope="col" className="px-6 py-3 text-left text-[11px] font-semibold text-gray-500 uppercase tracking-[0.2em] font-mono">Security</th>
                                        <th scope="col" className="px-6 py-3 text-left text-[11px] font-semibold text-gray-500 uppercase tracking-[0.2em] font-mono">Clients</th>
                                        <th scope="col" className="px-6 py-3 text-left text-[11px] font-semibold text-gray-500 uppercase tracking-[0.2em] font-mono">Status</th>
                                        <th scope="col" className="px-6 py-3 text-right text-[11px] font-semibold text-gray-500 uppercase tracking-[0.2em] font-mono">Actions</th>
                                    </tr>
                                </thead>
                                <tbody className="bg-white divide-y divide-gray-200">
                                    {loading ? (
                                        <tr>
                                            <td colSpan={7} className="px-6 py-12 text-center text-gray-500">
                                                Loading...
                                            </td>
                                        </tr>
                                    ) : networks.length === 0 ? (
                                        <tr>
                                            <td colSpan={7} className="px-6 py-12 text-center text-gray-500">
                                                No networks registered. Click "Register New WiFi" to add one.
                                            </td>
                                        </tr>
                                    ) : (
                                        networks.map((network) => {
                                            const isExpanded = expandedNetwork === network.wifiId;
                                            const clients = getClientsForNetwork(network.wifiId);
                                            const isTargeted = isUnderAttack && attackDetails.some(d =>
                                                d.targetBssid?.toUpperCase() === network.bssid.toUpperCase()
                                            );
                                            return (
                                                <React.Fragment key={network.wifiId}>
                                                    <tr
                                                        className={`hover:bg-gray-50 transition-colors cursor-pointer ${isExpanded ? 'bg-blue-50' : ''}`}
                                                        onClick={() => handleExpandNetwork(network.wifiId)}
                                                    >
                                                        <td className="px-3 py-4 whitespace-nowrap">
                                                            <ChevronRightIcon className={`h-5 w-5 text-gray-400 transition-transform duration-200 ${isExpanded ? 'rotate-90' : ''}`} />
                                                        </td>
                                                        <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{network.ssid}</td>
                                                        <td className="px-6 py-4 whitespace-nowrap text-sm font-mono text-gray-500">{network.bssid}</td>
                                                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${network.securityType === 'OPEN' ? 'bg-red-100 text-red-800' : 'bg-yellow-100 text-yellow-800'}`}>
                                                                {network.securityType}
                                                            </span>
                                                        </td>
                                                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                                            <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-600">
                                                                <UserGroupIcon className="h-3.5 w-3.5" />
                                                                {networkClients[network.wifiId] ? `${clients.length} clients` : 'Click to view'}
                                                            </span>
                                                        </td>
                                                        <td className="px-6 py-4 whitespace-nowrap">
                                                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold ${underAttack ? 'bg-red-100 text-red-800 animate-pulse' : 'bg-green-100 text-green-800'}`}>
                                                                {underAttack ? 'UNSAFE' : 'SAFE'}
                                                            </span>
                                                        </td>
                                                        <td
                                                            className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium relative z-10"
                                                            onClick={(e) => {
                                                                e.stopPropagation();
                                                                e.preventDefault();
                                                            }}
                                                        >
                                                            <button
                                                                type="button"
                                                                onClick={(e) => {
                                                                    e.stopPropagation();
                                                                    e.preventDefault();
                                                                    handleDelete(network.wifiId);
                                                                }}
                                                                className="relative p-2 text-gray-400 hover:text-red-600 hover:bg-red-50 rounded-md transition-colors isolate cursor-pointer"
                                                                title="Delete Network"
                                                            >
                                                                <TrashIcon className="h-5 w-5 pointer-events-none" />
                                                            </button>
                                                        </td>
                                                    </tr>
                                                    {/* Expanded Row - Connected Clients */}
                                                    {isExpanded && (
                                                        <tr className="bg-gray-50">
                                                            <td colSpan={7} className="px-6 py-4">
                                                                <div className="ml-8">
                                                                    <h4 className="text-sm font-semibold text-gray-700 mb-3 flex items-center gap-2">
                                                                        <UserGroupIcon className="h-4 w-4" />
                                                                        Connected Clients
                                                                    </h4>
                                                                    {loadingClients === network.wifiId ? (
                                                                        <div className="flex items-center gap-2 text-sm text-gray-500">
                                                                            <ArrowPathIcon className="h-4 w-4 animate-spin" />
                                                                            Loading connected clients...
                                                                        </div>
                                                                    ) : clientErrors[network.wifiId] ? (
                                                                        <div className="bg-amber-50 border border-amber-200 rounded-lg p-4">
                                                                            <p className="text-sm text-amber-800 font-medium">⚠️ Issue Loading Clients</p>
                                                                            <p className="text-sm text-amber-700 mt-1">
                                                                                {clientErrors[network.wifiId]}
                                                                            </p>
                                                                        </div>
                                                                    ) : clients.length === 0 ? (
                                                                        <div className="text-sm text-gray-500 italic">
                                                                            No clients currently connected.
                                                                        </div>
                                                                    ) : (
                                                                        <div className="bg-white rounded-lg border border-gray-200 overflow-hidden">
                                                                            <table className="min-w-full divide-y divide-gray-200">
                                                                                <thead className="bg-gray-100">
                                                                                    <tr>
                                                                                        <th className="px-4 py-2 text-left text-[11px] font-semibold text-gray-500 font-mono uppercase tracking-[0.2em]">Device</th>
                                                                                        <th className="px-4 py-2 text-left text-[11px] font-semibold text-gray-500 font-mono uppercase tracking-[0.2em]">MAC Address</th>
                                                                                        <th className="px-4 py-2 text-left text-[11px] font-semibold text-gray-500 font-mono uppercase tracking-[0.2em]">IP Address</th>
                                                                                        <th className="px-4 py-2 text-left text-[11px] font-semibold text-gray-500 font-mono uppercase tracking-[0.2em]">Signal</th>
                                                                                        <th className="px-4 py-2 text-left text-[11px] font-semibold text-gray-500 font-mono uppercase tracking-[0.2em]">Connected Since</th>
                                                                                    </tr>
                                                                                </thead>
                                                                                <tbody className="divide-y divide-gray-100">
                                                                                    {clients.map((client, idx) => (
                                                                                        <tr key={idx} className="hover:bg-gray-50">
                                                                                            <td className="px-4 py-3 whitespace-nowrap">
                                                                                                <div className="flex items-center gap-2">
                                                                                                    {(client.hostname?.toLowerCase().includes('iphone') || client.hostname?.toLowerCase().includes('android')) ? (
                                                                                                        <DevicePhoneMobileIcon className="h-4 w-4 text-gray-400" />
                                                                                                    ) : (
                                                                                                        <ComputerDesktopIcon className="h-4 w-4 text-gray-400" />
                                                                                                    )}
                                                                                                    <span className="text-sm font-medium text-gray-900">{client.hostname || 'Unknown'}</span>
                                                                                                </div>
                                                                                            </td>
                                                                                            <td className="px-4 py-2 whitespace-nowrap text-sm text-gray-500 font-mono">{client.macAddress}</td>
                                                                                            <td className="px-4 py-3 whitespace-nowrap text-sm text-gray-500">{client.ipAddress || '-'}</td>
                                                                                            <td className="px-4 py-3 whitespace-nowrap">
                                                                                                <span className={`px-2 py-1 rounded-full text-xs font-medium ${parseInt(client.signalStrength || "-100") > -60
                                                                                                    ? 'bg-green-100 text-green-800'
                                                                                                    : parseInt(client.signalStrength || "-100") > -75
                                                                                                        ? 'bg-yellow-100 text-yellow-800'
                                                                                                        : 'bg-red-100 text-red-800'
                                                                                                    }`}>
                                                                                                    {client.signalStrength || 'N/A'} dBm
                                                                                                </span>
                                                                                            </td>
                                                                                            <td className="px-4 py-3 whitespace-nowrap text-sm text-gray-500">
                                                                                                {new Date(client.connectionTime).toLocaleString()}
                                                                                            </td>
                                                                                        </tr>
                                                                                    ))}
                                                                                </tbody>
                                                                            </table>
                                                                        </div>
                                                                    )}
                                                                </div>
                                                            </td>
                                                        </tr>
                                                    )}
                                                </React.Fragment>
                                            );
                                        })
                                    )}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>


                {/* Detection Feed Section (Module 3 Integration) */}
                <div>
                    <div className="flex items-center justify-between mb-6">
                        <h3 className="text-xl font-bold text-gray-900">Recent Deauth Packets (Last Hour)</h3>
                        <button
                            disabled={clearing}
                            onClick={async () => {
                                if (window.confirm('Are you sure you want to clear all detection history?')) {
                                    setClearing(true);
                                    setClearSuccess(false);
                                    try {
                                        const response = await detectionService.clearEvents();
                                        if (response.success) {
                                            console.log('✅ Detection history cleared successfully');
                                            // Trigger feed refresh instead of full page reload
                                            setFeedRefreshTrigger(prev => prev + 1);
                                            setError(null);
                                            setClearSuccess(true);
                                            setTimeout(() => setClearSuccess(false), 2000);
                                        } else {
                                            console.error('❌ Failed to clear events:', response.error);
                                            setError(response.error || 'Failed to clear detection history');
                                        }
                                    } catch (err) {
                                        console.error('❌ Exception clearing events:', err);
                                        setError('Failed to clear detection history. Please check if the backend is running.');
                                    } finally {
                                        setClearing(false);
                                    }
                                }
                            }}
                            className={`text-sm font-medium px-3 py-1 border rounded transition-colors flex items-center gap-1.5 ${clearSuccess
                                ? 'text-green-600 border-green-300 bg-green-50'
                                : clearing
                                    ? 'text-gray-400 border-gray-200 bg-gray-50 cursor-not-allowed'
                                    : 'text-red-600 hover:text-red-800 border-red-200 hover:bg-red-50'
                                }`}
                        >
                            {clearing ? (
                                <>
                                    <ArrowPathIcon className="h-3.5 w-3.5 animate-spin" />
                                    Clearing...
                                </>
                            ) : clearSuccess ? (
                                <>
                                    <CheckCircleIcon className="h-3.5 w-3.5" />
                                    Cleared
                                </>
                            ) : (
                                'Clear History'
                            )}
                        </button>
                    </div>
                    <DetectionFeed refreshTrigger={feedRefreshTrigger} />
                </div>
            </main>
        </div >
    );
};

export default AdminDashboard;
