import React, { useState, useEffect, useCallback } from 'react';
import { XMarkIcon, ShieldExclamationIcon } from '@heroicons/react/24/solid';

export interface ToastData {
    id: string;
    severity: 'CRITICAL' | 'HIGH';
    attackerMac: string;
    targetBssid?: string;
    score: number;
    message?: string;
    timestamp: string;
}

interface ToastItemProps {
    toast: ToastData;
    onDismiss: (id: string) => void;
}

const TOAST_DURATION = 8000; // 8 seconds

const ToastItem: React.FC<ToastItemProps> = ({ toast, onDismiss }) => {
    const [progress, setProgress] = useState(100);
    const [visible, setVisible] = useState(false);

    useEffect(() => {
        // Trigger entrance animation
        const enterTimeout = setTimeout(() => setVisible(true), 10);

        // Countdown progress bar
        const startTime = Date.now();
        const interval = setInterval(() => {
            const elapsed = Date.now() - startTime;
            const remaining = Math.max(0, 100 - (elapsed / TOAST_DURATION) * 100);
            setProgress(remaining);
            if (remaining === 0) clearInterval(interval);
        }, 50);

        // Auto-dismiss
        const dismissTimeout = setTimeout(() => {
            setVisible(false);
            setTimeout(() => onDismiss(toast.id), 350); // wait for exit animation
        }, TOAST_DURATION);

        return () => {
            clearTimeout(enterTimeout);
            clearTimeout(dismissTimeout);
            clearInterval(interval);
        };
    }, [toast.id, onDismiss]);

    const isCritical = toast.severity === 'CRITICAL';

    return (
        <div
            style={{
                transform: visible ? 'translateX(0)' : 'translateX(110%)',
                opacity: visible ? 1 : 0,
                transition: 'transform 0.35s cubic-bezier(0.16, 1, 0.3, 1), opacity 0.35s ease',
            }}
            className={`relative w-80 rounded-xl overflow-hidden shadow-2xl border ${isCritical
                ? 'bg-gradient-to-br from-red-600 to-red-800 border-red-500'
                : 'bg-gradient-to-br from-orange-500 to-orange-700 border-orange-400'
                }`}
        >
            {/* Progress bar */}
            <div className="absolute top-0 left-0 h-1 bg-white/20 w-full">
                <div
                    className="h-full bg-white/70 transition-all"
                    style={{ width: `${progress}%`, transition: 'width 50ms linear' }}
                />
            </div>

            <div className="px-4 pt-5 pb-4">
                {/* Header */}
                <div className="flex items-start justify-between gap-2">
                    <div className="flex items-center gap-2">
                        <ShieldExclamationIcon className="h-5 w-5 text-white flex-shrink-0 animate-pulse" />
                        <span className="text-xs font-bold tracking-widest text-white/80 uppercase">
                            {isCritical ? '🚨 Attack Detected' : '⚠️ Likely Attack'}
                        </span>
                    </div>
                    <button
                        onClick={() => onDismiss(toast.id)}
                        className="text-white/60 hover:text-white transition-colors flex-shrink-0"
                        aria-label="Dismiss"
                    >
                        <XMarkIcon className="h-4 w-4" />
                    </button>
                </div>

                {/* Body */}
                <div className="mt-3 space-y-1">
                    <p className="text-white font-bold text-sm font-mono">{toast.attackerMac}</p>
                    {toast.targetBssid && (
                        <p className="text-white/70 text-xs">
                            Target: <span className="font-mono">{toast.targetBssid}</span>
                        </p>
                    )}
                    <div className="flex items-center gap-3 mt-2">
                        <span className="bg-white/20 text-white text-xs font-bold px-2 py-0.5 rounded-md">
                            Score: {toast.score}
                        </span>
                        <span className="bg-white/20 text-white text-xs font-bold px-2 py-0.5 rounded-md">
                            {toast.severity}
                        </span>
                    </div>
                </div>

                {/* Timestamp */}
                <p className="mt-3 text-white/50 text-[10px]">
                    {new Date(toast.timestamp).toLocaleTimeString()}
                </p>
            </div>
        </div>
    );
};

interface ToastContainerProps {
    toasts: ToastData[];
    onDismiss: (id: string) => void;
}

export const ToastContainer: React.FC<ToastContainerProps> = ({ toasts, onDismiss }) => {
    if (toasts.length === 0) return null;

    return (
        <div className="fixed top-4 right-4 z-50 flex flex-col gap-3 pointer-events-none">
            {toasts.map(toast => (
                <div key={toast.id} className="pointer-events-auto">
                    <ToastItem toast={toast} onDismiss={onDismiss} />
                </div>
            ))}
        </div>
    );
};

/** Hook to manage toast state — import and use in pages */
export function useToasts() {
    const [toasts, setToasts] = useState<ToastData[]>([]);

    const addToast = useCallback((data: Omit<ToastData, 'id'>) => {
        const id = `${Date.now()}-${Math.random()}`;
        setToasts(prev => [...prev, { ...data, id }]);
    }, []);

    const dismissToast = useCallback((id: string) => {
        setToasts(prev => prev.filter(t => t.id !== id));
    }, []);

    return { toasts, addToast, dismissToast };
}
