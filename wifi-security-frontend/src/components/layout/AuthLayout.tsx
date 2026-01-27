import React from 'react';
import { InfoPanel } from './InfoPanel';
import { cn } from '../../utils/cn';

interface AuthLayoutProps {
    children: React.ReactNode;
}

export const AuthLayout: React.FC<AuthLayoutProps> = ({ children }) => {
    return (
        <div className="min-h-screen flex items-center justify-center p-6 bg-slate-100">
            {/* Skip to main content link for accessibility */}
            <a
                href="#main-content"
                className="skip-link"
            >
                Skip to main content
            </a>

            {/* Main container with shadow */}
            <div className="max-w-6xl w-full bg-white rounded-3xl shadow-panel overflow-hidden flex flex-col lg:flex-row min-h-[750px]">
                {/* Left side - Info Panel (hidden on mobile) */}
                <div className="w-full lg:w-1/2">
                    <InfoPanel />
                </div>

                {/* Right side - Form Content */}
                <main
                    id="main-content"
                    className={cn(
                        'w-full lg:w-1/2 p-8 lg:p-16 xl:p-24',
                        'flex flex-col justify-center',
                        'bg-white'
                    )}
                >
                    {/* Mobile Logo (visible only on mobile) */}
                    <div className="lg:hidden mb-8 text-center">
                        <div className="inline-flex items-center gap-2">
                            <div className="flex h-10 w-10 items-center justify-center rounded-card bg-primary">
                                <svg
                                    className="h-6 w-6 text-white"
                                    fill="none"
                                    stroke="currentColor"
                                    viewBox="0 0 24 24"
                                >
                                    <path
                                        strokeLinecap="round"
                                        strokeLinejoin="round"
                                        strokeWidth={2}
                                        d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
                                    />
                                </svg>
                            </div>
                            <span className="text-h3 font-display text-slate-900">
                                WiFi Shield
                            </span>
                        </div>
                    </div>

                    {/* Form Container */}
                    <div className="w-full max-w-md mx-auto">
                        {children}
                    </div>
                </main>
            </div>
        </div>
    );
};

export default AuthLayout;
