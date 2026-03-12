import React, { useState } from 'react';
import { Dialog } from '@headlessui/react';
import {
    ClipboardDocumentIcon,
    CheckIcon,
    ExclamationTriangleIcon,
} from '@heroicons/react/24/outline';
import { Button, Card } from '../ui';
import { cn } from '../../utils/cn';

interface InstituteCodeSuccessProps {
    isOpen: boolean;
    instituteCode: string;
    instituteName: string;
    onContinue: () => void;
}

export const InstituteCodeSuccess: React.FC<InstituteCodeSuccessProps> = ({
    isOpen,
    instituteCode,
    instituteName,
    onContinue,
}) => {
    const [copied, setCopied] = useState(false);

    const handleCopy = async () => {
        try {
            await navigator.clipboard.writeText(instituteCode);
            setCopied(true);
            setTimeout(() => setCopied(false), 2000);
        } catch (err) {
            console.error('Failed to copy:', err);
        }
    };

    return (
        <Dialog
            open={isOpen}
            onClose={() => { }} // Prevent closing by clicking outside
            className="relative z-50"
        >
            {/* Backdrop */}
            <div
                className="fixed inset-0 bg-black/70 backdrop-blur-sm"
                aria-hidden="true"
            />

            {/* Modal container */}
            <div className="fixed inset-0 flex items-center justify-center p-4">
                <Dialog.Panel
                    className={cn(
                        'w-full max-w-md transform overflow-hidden',
                        'rounded-modal bg-background-secondary border border-border-default',
                        'p-6 shadow-xl',
                        'transition-all duration-modal ease-modal',
                        'animate-fade-in'
                    )}
                >
                    {/* Success icon */}
                    <div className="mx-auto mb-6 flex h-16 w-16 items-center justify-center rounded-full bg-success/10">
                        <svg
                            className="h-8 w-8 text-success"
                            fill="none"
                            stroke="currentColor"
                            viewBox="0 0 24 24"
                        >
                            <path
                                strokeLinecap="round"
                                strokeLinejoin="round"
                                strokeWidth={2}
                                d="M5 13l4 4L19 7"
                            />
                        </svg>
                    </div>

                    {/* Title */}
                    <Dialog.Title className="text-center">
                        <h2 className="text-h2 text-gray-900">
                            Institute Created Successfully!
                        </h2>
                    </Dialog.Title>

                    {/* Description */}
                    <Dialog.Description className="mt-2 text-center text-body text-gray-600">
                        Your institute <strong className="text-gray-900 font-bold">{instituteName}</strong> has been registered.
                    </Dialog.Description>

                    {/* Institute Code Card */}
                    <Card
                        variant="bordered"
                        className="mt-6 text-center bg-gray-100"
                        padding="md"
                    >
                        <p className="text-caption text-gray-500 uppercase tracking-wider mb-2">
                            Your Institute Code
                        </p>
                        <div className="flex items-center justify-center gap-3">
                            <span className="font-mono text-h1 text-primary font-bold tracking-wider">
                                {instituteCode}
                            </span>
                            <button
                                onClick={handleCopy}
                                className={cn(
                                    'flex items-center justify-center p-2 rounded-button',
                                    'transition-all duration-hover',
                                    copied
                                        ? 'bg-success/10 text-success'
                                        : 'bg-white/5 text-text-secondary hover:bg-white/10 hover:text-text-primary'
                                )}
                                aria-label="Copy code"
                            >
                                {copied ? (
                                    <CheckIcon className="h-5 w-5" />
                                ) : (
                                    <ClipboardDocumentIcon className="h-5 w-5" />
                                )}
                            </button>
                        </div>
                        {copied && (
                            <p className="mt-2 text-caption text-success animate-fade-in">
                                Copied to clipboard!
                            </p>
                        )}
                    </Card>

                    {/* Warning */}
                    <div className="mt-6 flex gap-3 rounded-card bg-warning/10 border border-warning/30 p-4">
                        <ExclamationTriangleIcon className="h-5 w-5 text-warning flex-shrink-0 mt-0.5" />
                        <div className="text-body-sm text-text-secondary">
                            <strong className="text-warning">Important:</strong> Share this code
                            with members who need to join your organization. Keep it secure and
                            only share with trusted personnel.
                        </div>
                    </div>

                    {/* Continue Button */}
                    <div className="mt-6">
                        <Button onClick={onContinue} fullWidth>
                            Continue to Dashboard
                        </Button>
                    </div>
                </Dialog.Panel>
            </div>
        </Dialog>
    );
};

export default InstituteCodeSuccess;
