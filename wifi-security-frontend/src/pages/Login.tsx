import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { AuthLayout } from '../components/layout/AuthLayout';
import { Button, Input, Alert } from '../components/ui';
import { PeekingMascot } from '../components/ui/PeekingMascot';
import { useAuth } from '../context/AuthContext';
import { loginSchema, LoginFormData } from '../utils/validationSchemas';
import { ShieldCheckIcon } from '@heroicons/react/24/outline';

export const Login: React.FC = () => {
    const navigate = useNavigate();
    const { login, isLoading, error, clearError, isAuthenticated, user } = useAuth();
    const [localError, setLocalError] = useState<string | null>(null);

    // Mascot states
    const [isEmailFocused, setIsEmailFocused] = useState(false);
    const [isPasswordFocused, setIsPasswordFocused] = useState(false);
    const [isTyping, setIsTyping] = useState(false);

    const {
        register,
        handleSubmit,
        formState: { errors },
        watch,
    } = useForm<LoginFormData>({
        resolver: zodResolver(loginSchema),
        mode: 'onChange',
    });

    // Watch password field for typing detection
    const passwordValue = watch('password');
    const emailValue = watch('email');

    // Detect typing
    useEffect(() => {
        if (emailValue || passwordValue) {
            setIsTyping(true);
            const timer = setTimeout(() => setIsTyping(false), 500);
            return () => clearTimeout(timer);
        }
    }, [emailValue, passwordValue]);

    // Redirect if already authenticated
    useEffect(() => {
        if (isAuthenticated && user) {
            const redirectPath = getRedirectPath(user.role);
            navigate(redirectPath, { replace: true });
        }
    }, [isAuthenticated, user, navigate]);

    const getRedirectPath = (role: string): string => {
        switch (role) {
            case 'ADMIN':
                return '/admin/dashboard';
            case 'VIEWER':
                return '/viewer/dashboard';
            case 'HOME_USER':
                return '/home/dashboard';
            default:
                return '/';
        }
    };

    const onSubmit = async (data: LoginFormData) => {
        setLocalError(null);
        clearError();

        const success = await login(data.email, data.password);

        if (!success) {
            setLocalError('Invalid email or password. Please try again.');
        }
    };

    const displayError = localError || error;

    // Mascot logic: peeks when email focused, hides eyes when password focused
    const isPeeking = isEmailFocused || (!isPasswordFocused && isTyping);
    const isHiding = isPasswordFocused;

    return (
        <AuthLayout>
            <div className="w-full">
                {/* Header with logo */}
                <div className="mb-8">
                    <div className="flex items-center justify-between mb-8">
                        <div className="flex items-center gap-3">
                            <ShieldCheckIcon className="h-8 w-8 text-primary" strokeWidth={1.5} />
                            <span className="text-xl font-bold text-slate-900 tracking-tight uppercase font-mono">
                                wifi shield
                            </span>
                        </div>
                        {/* Peeking Mascot */}
                        <div className="relative overflow-hidden h-12">
                            <PeekingMascot
                                isPeeking={isPeeking}
                                isHiding={isHiding}
                                className="w-12 h-12"
                            />
                        </div>
                    </div>
                    <h1 className="text-3xl font-bold text-slate-900 mb-2">Welcome back</h1>
                    <p className="text-slate-500 text-sm">
                        Sign in to your account to continue.
                    </p>
                </div>

                {/* Error Alert */}
                {displayError && (
                    <Alert
                        variant="error"
                        title="Login Failed"
                        onClose={() => {
                            setLocalError(null);
                            clearError();
                        }}
                        className="mb-6"
                    >
                        {displayError}
                    </Alert>
                )}

                {/* Login Form */}
                <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
                    <Input
                        {...register('email', {
                            onBlur: () => setIsEmailFocused(false),
                        })}
                        label="Email Address"
                        type="email"
                        placeholder="name@company.com"
                        autoComplete="email"
                        error={errors.email?.message}
                        onFocus={() => setIsEmailFocused(true)}
                    />

                    <Input
                        {...register('password', {
                            onBlur: () => setIsPasswordFocused(false),
                        })}
                        label="Password"
                        type="password"
                        placeholder="••••••••••••••••"
                        autoComplete="current-password"
                        error={errors.password?.message}
                        onFocus={() => setIsPasswordFocused(true)}
                    />

                    {/* Remember & Forgot Password */}
                    <div className="flex items-center justify-end py-2">
                        <Link
                            to="/forgot-password"
                            className="text-xs font-bold text-primary hover:text-primary-dark transition-colors"
                        >
                            Forgot password?
                        </Link>
                    </div>

                    {/* Submit Button */}
                    <div className="pt-4 space-y-6">
                        <Button type="submit" isLoading={isLoading} fullWidth>
                            Sign In
                            <svg className="w-4 h-4 ml-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14 5l7 7m0 0l-7 7m7-7H3" />
                            </svg>
                        </Button>

                        {/* Register Link */}
                        <p className="text-center text-sm text-slate-500">
                            Don't have an account?{' '}
                            <Link
                                to="/register"
                                className="text-primary font-semibold hover:text-primary-dark transition-colors"
                            >
                                Create one
                            </Link>
                        </p>
                    </div>
                </form>


            </div>
        </AuthLayout>
    );
};

export default Login;
