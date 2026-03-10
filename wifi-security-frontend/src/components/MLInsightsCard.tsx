import React, { useState, useEffect } from 'react';

const ML_API_URL = process.env.REACT_APP_ML_API_URL || 'http://localhost:5000';

interface ModelInfo {
    loaded: boolean;
    type: string;
}

interface MLStats {
    models: Record<string, ModelInfo>;
    models_loaded: number;
    total_predictions: number;
    attack_predictions: number;
    normal_predictions: number;
    average_confidence: number;
    model_agreement_rate: number;
}

const MODEL_DISPLAY_NAMES: Record<string, string> = {
    random_forest: 'Random Forest',
    xgboost: 'XGBoost',
    logistic_regression: 'Logistic Reg.',
    decision_tree: 'Decision Tree',
};

export const MLInsightsCard: React.FC = () => {
    const [stats, setStats] = useState<MLStats | null>(null);
    const [error, setError] = useState(false);

    const fetchStats = async () => {
        try {
            const res = await fetch(`${ML_API_URL}/model-stats`);
            if (res.ok) {
                const data = await res.json();
                setStats(data);
                setError(false);
            } else {
                setError(true);
            }
        } catch {
            setError(true);
        }
    };

    useEffect(() => {
        fetchStats();
        const interval = setInterval(fetchStats, 10_000); // refresh every 10s
        return () => clearInterval(interval);
    }, []);

    const TOTAL_MODELS = 4;
    const modelsLoaded = stats?.models_loaded ?? 0;

    return (
        <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
            {/* Header */}
            <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                    <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-purple-100">
                        {/* Brain icon via inline SVG */}
                        <svg className="h-5 w-5 text-purple-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
                                d="M9.75 3.104v5.714a2.25 2.25 0 01-.659 1.591L5 14.5M9.75 3.104c-.251.023-.501.05-.75.082m.75-.082a24.301 24.301 0 014.5 0m0 0v5.714c0 .597.237 1.17.659 1.591L19.8 15M14.25 3.104c.251.023.501.05.75.082M19.8 15l-1.52.965A2.25 2.25 0 0116.38 17H7.62a2.25 2.25 0 01-1.9-1.035L4.2 15m15.6 0l.705 1.41A5.25 5.25 0 0118 21H6a5.25 5.25 0 01-2.505-3.59L4.2 15" />
                        </svg>
                    </div>
                    <span className="text-sm font-semibold text-gray-700">ML Ensemble</span>
                </div>
                <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${error ? 'bg-red-100 text-red-600' : modelsLoaded === TOTAL_MODELS
                        ? 'bg-green-100 text-green-700'
                        : 'bg-yellow-100 text-yellow-700'
                    }`}>
                    {error ? 'Offline' : `${modelsLoaded}/${TOTAL_MODELS} loaded`}
                </span>
            </div>

            {error ? (
                <p className="text-sm text-gray-400 text-center py-2">ML service unavailable</p>
            ) : stats ? (
                <>
                    {/* Model health pills */}
                    <div className="flex flex-wrap gap-1 mb-4">
                        {Object.entries(MODEL_DISPLAY_NAMES).map(([key, label]) => {
                            const loaded = stats.models[key]?.loaded ?? false;
                            return (
                                <span key={key} className={`text-[10px] font-medium px-2 py-0.5 rounded-full ${loaded ? 'bg-green-50 text-green-700 border border-green-200'
                                        : 'bg-red-50 text-red-600 border border-red-200'
                                    }`}>
                                    {loaded ? '✓' : '✗'} {label}
                                </span>
                            );
                        })}
                    </div>

                    {/* Stats grid */}
                    <div className="grid grid-cols-2 gap-3">
                        <div className="bg-gray-50 rounded-lg p-3">
                            <p className="text-xs text-gray-400 font-medium">Total Predictions</p>
                            <p className="text-xl font-bold text-gray-900">{stats.total_predictions.toLocaleString()}</p>
                        </div>
                        <div className="bg-red-50 rounded-lg p-3">
                            <p className="text-xs text-red-400 font-medium">Attack Predictions</p>
                            <p className="text-xl font-bold text-red-700">{stats.attack_predictions.toLocaleString()}</p>
                        </div>
                        <div className="bg-purple-50 rounded-lg p-3">
                            <p className="text-xs text-purple-400 font-medium">Avg Confidence</p>
                            <p className="text-xl font-bold text-purple-700">
                                {(stats.average_confidence * 100).toFixed(1)}%
                            </p>
                        </div>
                        <div className="bg-blue-50 rounded-lg p-3">
                            <p className="text-xs text-blue-400 font-medium">Agreement Rate</p>
                            <p className="text-xl font-bold text-blue-700">
                                {(stats.model_agreement_rate * 100).toFixed(1)}%
                            </p>
                        </div>
                    </div>

                    {/* Agreement progress bar */}
                    <div className="mt-3">
                        <div className="flex justify-between text-xs text-gray-400 mb-1">
                            <span>Model Consensus</span>
                            <span>{(stats.model_agreement_rate * 100).toFixed(0)}%</span>
                        </div>
                        <div className="w-full bg-gray-100 rounded-full h-1.5">
                            <div
                                className="bg-gradient-to-r from-blue-500 to-purple-500 h-1.5 rounded-full transition-all duration-700"
                                style={{ width: `${(stats.model_agreement_rate * 100).toFixed(0)}%` }}
                            />
                        </div>
                    </div>
                </>
            ) : (
                <div className="flex items-center justify-center py-4">
                    <div className="w-4 h-4 border-2 border-purple-400 border-t-transparent rounded-full animate-spin" />
                </div>
            )}
        </div>
    );
};
