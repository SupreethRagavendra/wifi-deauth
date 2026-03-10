import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { AuthLayout } from '../components/layout/AuthLayout';
import { AccountTypeSelector } from '../components/auth/AccountTypeSelector';
import { InstituteAdminForm } from '../components/auth/InstituteAdminForm';
import { ViewerRegistrationForm } from '../components/auth/ViewerRegistrationForm';
import { HomeUserForm } from '../components/auth/HomeUserForm';
import { InstituteCodeSuccess } from '../components/auth/InstituteCodeSuccess';
import { Alert } from '../components/ui';
import { useAuth } from '../context/AuthContext';
import { authService } from '../services/api';
import { AccountType } from '../types';
import {
    InstituteAdminFormData,
    ViewerFormData,
    HomeUserFormData,
} from '../utils/validationSchemas';

export const Register: React.FC = () => {
    const navigate = useNavigate();
    const { setUser } = useAuth();

    const [accountType, setAccountType] = useState<AccountType>(null);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    // Success modal state for Institute Admin
    const [showSuccessModal, setShowSuccessModal] = useState(false);
    const [instituteCode, setInstituteCode] = useState('');
    const [instituteName, setInstituteName] = useState('');

    const handleAccountTypeChange = (type: AccountType) => {
        setAccountType(type);
        setError(null);
    };

    const handleBack = () => {
        setAccountType(null);
        setError(null);
    };

    // Institute Admin Registration
    const handleInstituteAdminSubmit = async (data: InstituteAdminFormData) => {
        setIsLoading(true);
        setError(null);

        try {
            const response = await authService.registerAdmin(data);

            if (response.success && response.data) {
                setUser(response.data.user);
                setInstituteCode(response.data.instituteCode);
                setInstituteName(data.instituteName);
                setShowSuccessModal(true);
            } else {
                setError(response.error || 'Registration failed. Please try again.');
            }
        } catch (err) {
            setError('An unexpected error occurred. Please try again.');
        } finally {
            setIsLoading(false);
        }
    };

    // Viewer Registration
    const handleViewerSubmit = async (data: ViewerFormData) => {
        setIsLoading(true);
        setError(null);

        try {
            const response = await authService.registerViewer(data);

            if (response.success && response.data) {
                setUser(response.data.user);
                navigate('/viewer/dashboard');
            } else {
                setError(response.error || 'Registration failed. Please try again.');
            }
        } catch (err) {
            setError('An unexpected error occurred. Please try again.');
        } finally {
            setIsLoading(false);
        }
    };

    // Verify Institute Code for Viewer
    const handleVerifyCode = async (code: string): Promise<string | null> => {
        try {
            const response = await authService.verifyInstituteCode(code);
            if (response.success && response.data?.valid) {
                return response.data.instituteName;
            }
            return null;
        } catch (err) {
            return null;
        }
    };

    // Home User Registration
    const handleHomeUserSubmit = async (data: HomeUserFormData) => {
        setIsLoading(true);
        setError(null);

        try {
            const response = await authService.registerHome(data);

            if (response.success && response.data) {
                setUser(response.data.user);
                navigate('/home/dashboard');
            } else {
                setError(response.error || 'Registration failed. Please try again.');
            }
        } catch (err) {
            setError('An unexpected error occurred. Please try again.');
        } finally {
            setIsLoading(false);
        }
    };

    // Continue after showing institute code
    const handleSuccessModalContinue = () => {
        setShowSuccessModal(false);
        navigate('/admin/dashboard');
    };

    const renderForm = () => {
        switch (accountType) {
            case 'institute_admin':
                return (
                    <InstituteAdminForm
                        onSubmit={handleInstituteAdminSubmit}
                        isLoading={isLoading}
                        onBack={handleBack}
                    />
                );
            case 'viewer':
                return (
                    <ViewerRegistrationForm
                        onSubmit={handleViewerSubmit}
                        onVerifyCode={handleVerifyCode}
                        isLoading={isLoading}
                        onBack={handleBack}
                    />
                );
            case 'home_user':
                return (
                    <HomeUserForm
                        onSubmit={handleHomeUserSubmit}
                        isLoading={isLoading}
                        onBack={handleBack}
                    />
                );
            default:
                return (
                    <AccountTypeSelector
                        value={accountType}
                        onChange={handleAccountTypeChange}
                    />
                );
        }
    };

    return (
        <AuthLayout>
            {/* Error Alert */}
            {error && (
                <Alert
                    variant="error"
                    title="Registration Error"
                    onClose={() => setError(null)}
                    className="mb-6"
                >
                    {error}
                </Alert>
            )}

            {/* Form */}
            {renderForm()}

            {/* Login Link */}
            <p className="mt-8 text-center text-body text-text-secondary">
                Already have an account?{' '}
                <Link
                    to="/login"
                    className="font-medium text-primary hover:text-primary-light transition-colors"
                >
                    Sign in
                </Link>
            </p>

            {/* Success Modal for Institute Admin */}
            <InstituteCodeSuccess
                isOpen={showSuccessModal}
                instituteCode={instituteCode}
                instituteName={instituteName}
                onContinue={handleSuccessModalContinue}
            />
        </AuthLayout>
    );
};

export default Register;
