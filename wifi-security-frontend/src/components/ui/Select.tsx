import React, { forwardRef } from 'react';
import { ChevronDownIcon } from '@heroicons/react/24/outline';
import { cn } from '../../utils/cn';

export interface SelectOption {
    value: string;
    label: string;
}

export interface SelectProps
    extends Omit<React.SelectHTMLAttributes<HTMLSelectElement>, 'size'> {
    label?: string;
    error?: string;
    helperText?: string;
    options: SelectOption[];
    placeholder?: string;
    size?: 'sm' | 'md' | 'lg';
}

const sizeStyles = {
    sm: 'px-3 py-2 text-body-sm min-h-[36px]',
    md: 'px-4 py-3.5 text-body min-h-[44px]',
    lg: 'px-5 py-4 text-body-lg min-h-[52px]',
};

export const Select = forwardRef<HTMLSelectElement, SelectProps>(
    (
        {
            className,
            label,
            error,
            helperText,
            options,
            placeholder = 'Select an option',
            size = 'md',
            id,
            disabled,
            ...props
        },
        ref
    ) => {
        const selectId = id || `select-${label?.toLowerCase().replace(/\s/g, '-')}`;
        const helperId = `${selectId}-helper`;
        const errorId = `${selectId}-error`;

        return (
            <div className="w-full">
                {/* Label */}
                {label && (
                    <label
                        htmlFor={selectId}
                        className="mb-2 block text-body-sm font-medium text-text-secondary"
                    >
                        {label}
                    </label>
                )}

                {/* Select wrapper */}
                <div className="relative">
                    <select
                        ref={ref}
                        id={selectId}
                        disabled={disabled}
                        aria-invalid={error ? 'true' : 'false'}
                        aria-describedby={error ? errorId : helperText ? helperId : undefined}
                        className={cn(
                            // Base styles
                            'w-full appearance-none rounded-input border bg-white/5 text-text-primary',
                            'transition-all duration-focus ease-out',
                            'focus:outline-none focus:ring-4 focus:ring-primary/15',
                            // Size
                            sizeStyles[size],
                            'pr-10', // Space for chevron
                            // States
                            error
                                ? 'border-danger focus:border-danger focus:ring-danger/15'
                                : 'border-border-default hover:border-border-hover focus:border-primary',
                            // Disabled
                            disabled && 'cursor-not-allowed opacity-50',
                            className
                        )}
                        {...props}
                    >
                        <option value="" disabled className="bg-background-secondary text-text-muted">
                            {placeholder}
                        </option>
                        {options.map((option) => (
                            <option
                                key={option.value}
                                value={option.value}
                                className="bg-background-secondary text-text-primary"
                            >
                                {option.label}
                            </option>
                        ))}
                    </select>

                    {/* Chevron icon */}
                    <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center pr-3">
                        <ChevronDownIcon className="h-5 w-5 text-text-muted" />
                    </div>
                </div>

                {/* Error message */}
                {error && (
                    <p
                        id={errorId}
                        role="alert"
                        className="mt-2 flex items-center gap-1.5 text-body-sm text-danger"
                    >
                        <svg
                            className="h-4 w-4 flex-shrink-0"
                            fill="currentColor"
                            viewBox="0 0 20 20"
                        >
                            <path
                                fillRule="evenodd"
                                d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z"
                                clipRule="evenodd"
                            />
                        </svg>
                        {error}
                    </p>
                )}

                {/* Helper text */}
                {helperText && !error && (
                    <p id={helperId} className="mt-2 text-body-sm text-text-muted">
                        {helperText}
                    </p>
                )}
            </div>
        );
    }
);

Select.displayName = 'Select';

export default Select;
