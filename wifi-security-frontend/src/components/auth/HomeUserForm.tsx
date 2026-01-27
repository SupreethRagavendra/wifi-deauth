import React, { useEffect, useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { Button, Input } from '../ui';
import {
    homeUserSchema,
    HomeUserFormData,
    calculatePasswordStrength,
} from '../../utils/validationSchemas';
import { cn } from '../../utils/cn';

interface HomeUserFormProps {
    onSubmit: (data: HomeUserFormData) => Promise<void>;
    isLoading?: boolean;
    onBack?: () => void;
}

export const HomeUserForm: React.FC<HomeUserFormProps> = ({
    onSubmit,
    isLoading = false,
    onBack,
}) => {
    const [passwordStrength, setPasswordStrength] = useState({
        score: 0,
        label: '',
        color: '',
    });

    const {
        register,
        handleSubmit,
        watch,
        formState: { errors },
    } = useForm<HomeUserFormData>({
        resolver: zodResolver(homeUserSchema),
        mode: 'onChange',
        defaultValues: {
            name: '',
            email: '',
            password: '',
            confirmPassword: '',
            networkName: '',
        },
    });

    const password = watch('password');

    useEffect(() => {
        if (password) {
            setPasswordStrength(calculatePasswordStrength(password));
        } else {
            setPasswordStrength({ score: 0, label: '', color: '' });
        }
    }, [password]);

    const handleFormSubmit = async (data: HomeUserFormData) => {
        await onSubmit(data);
    };

    return (
        <form onSubmit={handleSubmit(handleFormSubmit)} className="w-full space-y-6">
            <div className="space-y-4">
                <div className="mb-4">
                    <h3 className="text-h3 text-text-primary">Personal Account</h3>
                    <p className="text-body-sm text-text-secondary mt-1">
                        Protect your home WiFi network
                    </p>
                </div>

                <Input
                    label="Your Name"
                    placeholder="Enter your full name"
                    error={errors.name?.message}
                    {...register('name')}
                />

                <Input
                    label="Email Address"
                    type="email"
                    placeholder="you@example.com"
                    error={errors.email?.message}
                    {...register('email')}
                />

                <div className="space-y-2">
                    <Input
                        label="Password"
                        type="password"
                        placeholder="Create a strong password"
                        error={errors.password?.message}
                        helperText="Must be at least 8 characters with uppercase and number"
                        {...register('password')}
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
                    error={errors.confirmPassword?.message}
                    {...register('confirmPassword')}
                />

                <Input
                    label="Network Name (Optional)"
                    placeholder="My Home Network"
                    helperText="This helps you identify your network in the dashboard"
                    {...register('networkName')}
                />
            </div>

            {/* Actions */}
            <div className="flex gap-4 pt-4">
                {onBack && (
                    <Button type="button" variant="ghost" onClick={onBack}>
                        Back
                    </Button>
                )}
                <Button type="submit" isLoading={isLoading} fullWidth>
                    Create Account
                </Button>
            </div>
        </form>
    );
};

export default HomeUserForm;
