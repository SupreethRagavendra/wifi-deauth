import React, { useState, useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { CheckCircleIcon } from '@heroicons/react/24/outline';
import { Button, Input, Alert } from '../ui';
import {
    viewerSchema,
    ViewerFormData,
    instituteCodeSchema,
    InstituteCodeFormData,
    calculatePasswordStrength,
} from '../../utils/validationSchemas';
import { cn } from '../../utils/cn';

interface ViewerRegistrationFormProps {
    onSubmit: (data: ViewerFormData) => Promise<void>;
    onVerifyCode: (code: string) => Promise<string | null>; // Returns institute name or null
    isLoading?: boolean;
    onBack?: () => void;
}

export const ViewerRegistrationForm: React.FC<ViewerRegistrationFormProps> = ({
    onSubmit,
    onVerifyCode,
    isLoading = false,
    onBack,
}) => {
    const [step, setStep] = useState<'verify' | 'register'>('verify');
    const [verifiedInstitute, setVerifiedInstitute] = useState<string | null>(null);
    const [verifyError, setVerifyError] = useState<string | null>(null);
    const [isVerifying, setIsVerifying] = useState(false);
    const [passwordStrength, setPasswordStrength] = useState({
        score: 0,
        label: '',
        color: '',
    });

    // Code verification form
    const codeForm = useForm<InstituteCodeFormData>({
        resolver: zodResolver(instituteCodeSchema),
        mode: 'onChange',
    });

    // Registration form
    const registerForm = useForm<ViewerFormData>({
        resolver: zodResolver(viewerSchema),
        mode: 'onChange',
    });

    const password = registerForm.watch('password');

    useEffect(() => {
        if (password) {
            setPasswordStrength(calculatePasswordStrength(password));
        } else {
            setPasswordStrength({ score: 0, label: '', color: '' });
        }
    }, [password]);

    const handleVerifyCode = async (data: InstituteCodeFormData) => {
        setIsVerifying(true);
        setVerifyError(null);

        try {
            const instituteName = await onVerifyCode(data.code);
            if (instituteName) {
                setVerifiedInstitute(instituteName);
                registerForm.setValue('instituteCode', data.code);
                setStep('register');
            } else {
                setVerifyError('Invalid institute code. Please check and try again.');
            }
        } catch (error) {
            setVerifyError('Failed to verify code. Please try again.');
        } finally {
            setIsVerifying(false);
        }
    };

    const handleFormSubmit = async (data: ViewerFormData) => {
        await onSubmit(data);
    };

    if (step === 'verify') {
        return (
            <form onSubmit={codeForm.handleSubmit(handleVerifyCode)} className="w-full space-y-6">
                <div>
                    <h3 className="text-h3 text-text-primary">Join Your Organization</h3>
                    <p className="text-body-sm text-text-secondary mt-1">
                        Enter the invite code provided by your organization administrator
                    </p>
                </div>

                <Input
                    label="Institute Code"
                    placeholder="Enter code (e.g., ABC123)"
                    error={codeForm.formState.errors.code?.message}
                    helperText="The code should be uppercase letters and numbers"
                    {...codeForm.register('code', {
                        onChange: (e) => {
                            e.target.value = e.target.value.toUpperCase();
                        },
                    })}
                />

                {verifyError && (
                    <Alert variant="error" title="Verification Failed">
                        {verifyError}
                    </Alert>
                )}

                <div className="flex gap-4 pt-4">
                    {onBack && (
                        <Button type="button" variant="ghost" onClick={onBack}>
                            Back
                        </Button>
                    )}
                    <Button type="submit" isLoading={isVerifying} fullWidth>
                        Verify Code
                    </Button>
                </div>
            </form>
        );
    }

    return (
        <form onSubmit={registerForm.handleSubmit(handleFormSubmit)} className="w-full space-y-6">
            {/* Success Alert */}
            <Alert variant="success" title="Organization Verified">
                <div className="flex items-center gap-2">
                    <CheckCircleIcon className="h-5 w-5 text-success" />
                    <span>
                        You are joining <strong className="text-text-primary">{verifiedInstitute}</strong>
                    </span>
                </div>
            </Alert>

            {/* Registration Form */}
            <div className="space-y-4">
                <div className="mb-4">
                    <h3 className="text-h3 text-text-primary">Complete Your Profile</h3>
                    <p className="text-body-sm text-text-secondary mt-1">
                        Create your account to start monitoring
                    </p>
                </div>

                <Input
                    label="Your Name"
                    placeholder="Enter your full name"
                    error={registerForm.formState.errors.name?.message}
                    {...registerForm.register('name')}
                />

                <Input
                    label="Email Address"
                    type="email"
                    placeholder="you@example.com"
                    error={registerForm.formState.errors.email?.message}
                    {...registerForm.register('email')}
                />

                <div className="space-y-2">
                    <Input
                        label="Password"
                        type="password"
                        placeholder="Create a password"
                        error={registerForm.formState.errors.password?.message}
                        helperText="Must be at least 8 characters with uppercase and number"
                        {...registerForm.register('password')}
                    />

                    {/* Password Strength Indicator */}
                    {password && (
                        <div className="space-y-1.5">
                            <div className="flex items-center justify-between text-caption">
                                <span className="text-text-muted">Password strength</span>
                                <span
                                    className={cn(
                                        'font-medium',
                                        passwordStrength.color.replace('bg-', 'text-')
                                    )}
                                >
                                    {passwordStrength.label}
                                </span>
                            </div>
                            <div className="h-1.5 w-full rounded-full bg-background-tertiary overflow-hidden">
                                <div
                                    className={cn(
                                        'h-full rounded-full transition-all duration-300',
                                        passwordStrength.color
                                    )}
                                    style={{ width: `${passwordStrength.score}%` }}
                                />
                            </div>
                        </div>
                    )}
                </div>

                <Input
                    label="Confirm Password"
                    type="password"
                    placeholder="Confirm your password"
                    error={registerForm.formState.errors.confirmPassword?.message}
                    {...registerForm.register('confirmPassword')}
                />
            </div>

            {/* Actions */}
            <div className="flex gap-4 pt-4">
                <Button
                    type="button"
                    variant="ghost"
                    onClick={() => {
                        setStep('verify');
                        setVerifiedInstitute(null);
                    }}
                >
                    Back
                </Button>
                <Button type="submit" isLoading={isLoading} fullWidth>
                    Complete Registration
                </Button>
            </div>
        </form>
    );
};

export default ViewerRegistrationForm;
