import React, { useEffect, useState } from 'react';
import { useForm, Controller } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { Button, Input, Select } from '../ui';
import {
    instituteAdminSchema,
    InstituteAdminFormData,
    calculatePasswordStrength,
} from '../../utils/validationSchemas';
import { cn } from '../../utils/cn';

interface InstituteAdminFormProps {
    onSubmit: (data: InstituteAdminFormData) => Promise<void>;
    isLoading?: boolean;
    onBack?: () => void;
}

const instituteTypes = [
    { value: 'COLLEGE', label: 'College / University' },
    { value: 'SCHOOL', label: 'School (K-12)' },
    { value: 'COMPANY', label: 'Company / Enterprise' },
];

export const InstituteAdminForm: React.FC<InstituteAdminFormProps> = ({
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
        control,
        watch,
        formState: { errors },
    } = useForm<InstituteAdminFormData>({
        resolver: zodResolver(instituteAdminSchema),
        mode: 'onChange',
        defaultValues: {
            instituteName: '',
            instituteType: undefined,
            location: '',
            adminName: '',
            email: '',
            password: '',
            confirmPassword: '',
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

    const handleFormSubmit = async (data: InstituteAdminFormData) => {
        await onSubmit(data);
    };

    return (
        <form onSubmit={handleSubmit(handleFormSubmit)} className="w-full space-y-6">
            {/* Institute Information Section */}
            <div className="space-y-4">
                <div className="mb-4">
                    <h3 className="text-h3 text-text-primary">Institute Information</h3>
                    <p className="text-body-sm text-text-secondary mt-1">
                        Tell us about your organization
                    </p>
                </div>

                <Input
                    label="Institute Name"
                    placeholder="Enter your institute name"
                    error={errors.instituteName?.message}
                    {...register('instituteName')}
                />

                <Controller
                    name="instituteType"
                    control={control}
                    render={({ field }) => (
                        <Select
                            label="Institute Type"
                            placeholder="Select institute type"
                            options={instituteTypes}
                            error={errors.instituteType?.message}
                            value={field.value || ''}
                            onChange={field.onChange}
                        />
                    )}
                />

                <Input
                    label="Location (Optional)"
                    placeholder="City, Country"
                    {...register('location')}
                />
            </div>

            {/* Divider */}
            <div className="border-t border-border-default" />

            {/* Admin Details Section */}
            <div className="space-y-4">
                <div className="mb-4">
                    <h3 className="text-h3 text-text-primary">Admin Details</h3>
                    <p className="text-body-sm text-text-secondary mt-1">
                        Create your administrator account
                    </p>
                </div>

                <Input
                    label="Your Name"
                    placeholder="Enter your full name"
                    error={errors.adminName?.message}
                    {...register('adminName')}
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
            </div>

            {/* Actions */}
            <div className="flex gap-4 pt-4">
                {onBack && (
                    <Button type="button" variant="ghost" onClick={onBack}>
                        Back
                    </Button>
                )}
                <Button type="submit" isLoading={isLoading} fullWidth>
                    Create Institute Account
                </Button>
            </div>
        </form>
    );
};

export default InstituteAdminForm;
