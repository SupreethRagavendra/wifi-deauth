import React from 'react';
import { cn } from '../../utils/cn';

interface PeekingMascotProps {
    isPeeking: boolean;
    isHiding: boolean;
    className?: string;
}

export const PeekingMascot: React.FC<PeekingMascotProps> = ({
    isPeeking,
    isHiding,
    className,
}) => {
    return (
        <div className={cn('relative w-16 h-16', className)}>
            <svg
                viewBox="0 0 64 64"
                className={cn(
                    'w-full h-full transition-transform duration-300 ease-out',
                    isPeeking && !isHiding && 'translate-y-0',
                    !isPeeking && 'translate-y-8',
                    isHiding && 'translate-y-0'
                )}
            >
                {/* Robot body - Shield shape */}
                <path
                    d="M32 8L12 16v16c0 12 8.6 22 20 26 11.4-4 20-14 20-26V16L32 8z"
                    fill="#2563eb"
                    stroke="#1d4ed8"
                    strokeWidth="2"
                />

                {/* Face plate */}
                <ellipse cx="32" cy="32" rx="14" ry="12" fill="#f1f5f9" />

                {/* Eyes container */}
                <g className={cn(
                    'transition-all duration-200',
                    isHiding && 'opacity-0'
                )}>
                    {/* Left eye */}
                    <ellipse
                        cx="26"
                        cy="30"
                        rx="4"
                        ry={isPeeking && !isHiding ? 5 : 0.5}
                        fill="#1e293b"
                        className="transition-all duration-200"
                    />
                    {/* Right eye */}
                    <ellipse
                        cx="38"
                        cy="30"
                        rx="4"
                        ry={isPeeking && !isHiding ? 5 : 0.5}
                        fill="#1e293b"
                        className="transition-all duration-200"
                    />

                    {/* Eye shine */}
                    {isPeeking && !isHiding && (
                        <>
                            <circle cx="24" cy="28" r="1.5" fill="white" />
                            <circle cx="36" cy="28" r="1.5" fill="white" />
                        </>
                    )}
                </g>

                {/* Hands covering eyes when hiding */}
                <g className={cn(
                    'transition-all duration-300',
                    isHiding ? 'opacity-100' : 'opacity-0'
                )}>
                    {/* Left hand */}
                    <ellipse cx="24" cy="30" rx="8" ry="6" fill="#2563eb" stroke="#1d4ed8" strokeWidth="1" />
                    {/* Right hand */}
                    <ellipse cx="40" cy="30" rx="8" ry="6" fill="#2563eb" stroke="#1d4ed8" strokeWidth="1" />
                </g>

                {/* Antenna with WiFi signal */}
                <g>
                    <line x1="32" y1="8" x2="32" y2="2" stroke="#1d4ed8" strokeWidth="2" />
                    <circle cx="32" cy="0" r="2" fill="#3b82f6" />
                    {/* WiFi waves from antenna */}
                    <path
                        d="M28 -2 a6 6 0 0 1 8 0"
                        stroke="#93c5fd"
                        strokeWidth="1.5"
                        fill="none"
                        strokeLinecap="round"
                        className="animate-pulse"
                    />
                </g>

                {/* Smile */}
                <path
                    d={isPeeking && !isHiding ? "M28 38 Q32 42 36 38" : "M28 38 Q32 39 36 38"}
                    stroke="#1e293b"
                    strokeWidth="2"
                    strokeLinecap="round"
                    fill="none"
                    className="transition-all duration-200"
                />
            </svg>
        </div>
    );
};

export default PeekingMascot;
