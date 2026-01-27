import React from 'react';
import {
    BuildingOfficeIcon,
    UserGroupIcon,
    HomeIcon,
} from '@heroicons/react/24/outline';
import { RadioGroup, RadioOption } from '../ui';
import { AccountType } from '../../types';

interface AccountTypeSelectorProps {
    value: AccountType;
    onChange: (value: AccountType) => void;
}

const accountTypeOptions: RadioOption[] = [
    {
        value: 'institute_admin',
        label: 'Institute Administrator',
        description:
            'Register your institution (college, school, or company) and manage network security for your organization.',
        icon: <BuildingOfficeIcon className="h-6 w-6" />,
    },
    {
        value: 'viewer',
        label: 'Organization Viewer',
        description:
            'Join an existing organization using an invite code to monitor network activity.',
        icon: <UserGroupIcon className="h-6 w-6" />,
    },
    {
        value: 'home_user',
        label: 'Home User',
        description:
            'Secure your personal home network with WiFi deauthentication protection.',
        icon: <HomeIcon className="h-6 w-6" />,
    },
];

export const AccountTypeSelector: React.FC<AccountTypeSelectorProps> = ({
    value,
    onChange,
}) => {
    return (
        <div className="w-full">
            <h2 className="text-h2 text-text-primary mb-2">Create your account</h2>
            <p className="text-body text-text-secondary mb-6">
                Choose the type of account that best fits your needs
            </p>

            <RadioGroup
                value={value || ''}
                onChange={(val) => onChange(val as AccountType)}
                options={accountTypeOptions}
                orientation="vertical"
            />
        </div>
    );
};

export default AccountTypeSelector;
