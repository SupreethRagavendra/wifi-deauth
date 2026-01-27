import React from 'react';

import { cn } from '../../utils/cn';

export const InfoPanel: React.FC = () => {
    return (
        <div
            className={cn(
                'relative hidden lg:flex flex-col justify-center items-center',
                'h-full min-h-screen p-12',
                'tech-gradient',
                'overflow-hidden'
            )}
        >
            {/* Circuit pattern overlay */}
            <div className="absolute inset-0 circuit-pattern pointer-events-none" />

            {/* Data points decorations */}
            <div className="data-point" style={{ top: '25%', left: '25%' }} />
            <div className="data-point" style={{ top: '33%', right: '25%' }} />
            <div className="data-point" style={{ bottom: '25%', left: '33%' }} />
            <div className="data-point" style={{ bottom: '50%', right: '50%' }} />
            <div className="data-point" style={{ top: '40px', right: '40px' }} />
            <div className="data-point" style={{ bottom: '40px', left: '40px' }} />

            {/* Main content */}
            <div className="relative z-10 flex flex-col items-center text-center">
                {/* Shield with WiFi icon - Fixed design */}
                <div className="w-72 h-72 relative mb-10 flex items-center justify-center">
                    {/* Geometric frame */}
                    <div className="absolute inset-0 border border-white/20 rotate-45" />
                    <div className="absolute inset-4 border border-white/10" />

                    {/* Shield container with proper icon */}
                    <div className="relative bg-white/10 backdrop-blur-md border border-white/20 p-8 rounded-2xl shield-glow">
                        {/* Custom Shield + WiFi SVG */}
                        <svg
                            className="w-24 h-24 text-white"
                            viewBox="0 0 64 64"
                            fill="none"
                            xmlns="http://www.w3.org/2000/svg"
                        >
                            {/* Shield outline */}
                            <path
                                d="M32 4L8 14v18c0 14.4 10.4 26.4 24 30 13.6-3.6 24-15.6 24-30V14L32 4z"
                                stroke="currentColor"
                                strokeWidth="2.5"
                                fill="rgba(255,255,255,0.1)"
                            />
                            {/* WiFi waves inside shield */}
                            <g transform="translate(32, 38)">
                                {/* Bottom dot */}
                                <circle cx="0" cy="8" r="3" fill="currentColor" />
                                {/* Wave 1 */}
                                <path
                                    d="M-6 2a8.5 8.5 0 0 1 12 0"
                                    stroke="currentColor"
                                    strokeWidth="2.5"
                                    strokeLinecap="round"
                                    fill="none"
                                />
                                {/* Wave 2 */}
                                <path
                                    d="M-12 -4a15 15 0 0 1 24 0"
                                    stroke="currentColor"
                                    strokeWidth="2.5"
                                    strokeLinecap="round"
                                    fill="none"
                                />
                                {/* Wave 3 */}
                                <path
                                    d="M-18 -10a22 22 0 0 1 36 0"
                                    stroke="currentColor"
                                    strokeWidth="2.5"
                                    strokeLinecap="round"
                                    fill="none"
                                />
                            </g>
                        </svg>
                    </div>
                </div>

                {/* Title */}
                <h2 className="text-3xl font-bold text-white mb-3 tracking-tight font-mono uppercase">
                    WiFi Shield
                </h2>

                {/* Divider */}
                <div className="h-1 w-12 bg-white/60 mb-6" />

                {/* Description */}
                <p className="text-blue-50 text-center max-w-sm leading-relaxed font-light">
                    Secure access gateway for enterprise network infrastructure.
                    <span className="block mt-2 text-blue-200 text-sm font-mono">
                        SYSTEM STATUS: ENCRYPTED
                    </span>
                </p>
            </div>

            {/* Bottom info bar */}
            <div className="absolute bottom-10 text-blue-200/60 text-[10px] font-mono flex items-center gap-8 uppercase tracking-widest">
                <span className="flex items-center gap-2 border-l border-white/30 pl-2">
                    Protocol: AES-256-GCM
                </span>
                <span className="flex items-center gap-2 border-l border-white/30 pl-2">
                    Node: US-EAST-01
                </span>
            </div>
        </div>
    );
};

export default InfoPanel;
