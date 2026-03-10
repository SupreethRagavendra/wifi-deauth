import React, { useState } from 'react';
import { AppNavbar } from '../components/layout/AppNavbar';
import { DetectionFeed } from '../components/DetectionFeed';
import { detectionService } from '../services/api';
import { ArrowPathIcon, CheckCircleIcon } from '@heroicons/react/24/solid';

export const ViewerDetection: React.FC = () => {
    const [feedRefreshTrigger, setFeedRefreshTrigger] = useState(0);
    const [clearing, setClearing] = useState(false);
    const [clearSuccess, setClearSuccess] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const handleClear = async () => {
        if (!window.confirm('Are you sure you want to clear all detection history?')) return;
        setClearing(true);
        setClearSuccess(false);
        try {
            const response = await detectionService.clearEvents();
            if (response.success) {
                setFeedRefreshTrigger(prev => prev + 1);
                setError(null);
                setClearSuccess(true);
                setTimeout(() => setClearSuccess(false), 2000);
            } else {
                setError(response.error || 'Failed to clear detection history');
            }
        } catch (err) {
            setError('Failed to clear detection history. Please check if the backend is running.');
        } finally {
            setClearing(false);
        }
    };

    return (
        <div className="min-h-screen bg-background-primary">
            <AppNavbar />
            <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
                {/* Page Title + Clear Button */}
                <div className="mb-6 flex items-center justify-between">
                    <div>
                        <h1 className="text-h1 text-text-primary">Detection Monitor</h1>
                        <p className="text-body text-text-secondary mt-2">
                            Real-time threat detection for your assigned network.
                        </p>
                    </div>
                    <button
                        disabled={clearing}
                        onClick={handleClear}
                        className={`text-sm font-medium px-3 py-1.5 border rounded-lg transition-colors flex items-center gap-1.5 ${clearSuccess
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

                {error && (
                    <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-lg text-red-700 text-sm">
                        {error}
                    </div>
                )}

                <DetectionFeed refreshTrigger={feedRefreshTrigger} />
            </main>
        </div>
    );
};
