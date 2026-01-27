import React from 'react';
import {
    CheckCircleIcon,
    ExclamationTriangleIcon,
    InformationCircleIcon,
    XCircleIcon,
    XMarkIcon,
} from '@heroicons/react/24/outline';
import { cn } from '../../utils/cn';

export interface AlertProps extends React.HTMLAttributes<HTMLDivElement> {
    variant?: 'success' | 'error' | 'warning' | 'info';
    title?: string;
    onClose?: () => void;
}

const variantStyles = {
    success: {
        container: 'bg-green-50 border-green-200',
        icon: 'text-green-600',
        title: 'text-green-800',
        text: 'text-green-700',
    },
    error: {
        container: 'bg-red-50 border-red-200',
        icon: 'text-red-600',
        title: 'text-red-800',
        text: 'text-red-700',
    },
    warning: {
        container: 'bg-amber-50 border-amber-200',
        icon: 'text-amber-600',
        title: 'text-amber-800',
        text: 'text-amber-700',
    },
    info: {
        container: 'bg-blue-50 border-blue-200',
        icon: 'text-blue-600',
        title: 'text-blue-800',
        text: 'text-blue-700',
    },
};

const icons = {
    success: CheckCircleIcon,
    error: XCircleIcon,
    warning: ExclamationTriangleIcon,
    info: InformationCircleIcon,
};

export const Alert = React.forwardRef<HTMLDivElement, AlertProps>(
    (
        { className, variant = 'info', title, onClose, children, ...props },
        ref
    ) => {
        const styles = variantStyles[variant];
        const Icon = icons[variant];

        return (
            <div
                ref={ref}
                role="alert"
                className={cn(
                    'relative flex gap-3 rounded-input border p-4',
                    'animate-fade-in',
                    styles.container,
                    className
                )}
                {...props}
            >
                {/* Icon */}
                <Icon className={cn('h-5 w-5 flex-shrink-0 mt-0.5', styles.icon)} />

                {/* Content */}
                <div className="flex-1 min-w-0">
                    {title && (
                        <h4 className={cn('text-sm font-semibold mb-1', styles.title)}>
                            {title}
                        </h4>
                    )}
                    <div className={cn('text-sm', styles.text)}>{children}</div>
                </div>

                {/* Close button */}
                {onClose && (
                    <button
                        type="button"
                        onClick={onClose}
                        className={cn(
                            'flex-shrink-0 transition-colors',
                            styles.icon,
                            'hover:opacity-70'
                        )}
                        aria-label="Dismiss"
                    >
                        <XMarkIcon className="h-5 w-5" />
                    </button>
                )}
            </div>
        );
    }
);

Alert.displayName = 'Alert';

export default Alert;
