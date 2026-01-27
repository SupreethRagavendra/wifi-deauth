import React, { useState, forwardRef } from 'react';
import { EyeIcon, EyeSlashIcon, AtSymbolIcon, KeyIcon } from '@heroicons/react/24/outline';
import { cn } from '../../utils/cn';

export interface InputProps
    extends Omit<React.InputHTMLAttributes<HTMLInputElement>, 'size'> {
    label?: string;
    error?: string;
    success?: boolean;
    helperText?: string;
    leftIcon?: React.ReactNode;
    rightIcon?: React.ReactNode;
    size?: 'sm' | 'md' | 'lg';
}

const sizeStyles = {
    sm: 'pl-12 pr-4 py-3 text-sm min-h-[44px]',
    md: 'pl-12 pr-4 py-4 text-sm min-h-[52px]',
    lg: 'pl-12 pr-4 py-5 text-base min-h-[60px]',
};

export const Input = forwardRef<HTMLInputElement, InputProps>(
    (
        {
            className,
            type = 'text',
            label,
            error,
            success,
            helperText,
            leftIcon,
            rightIcon,
            size = 'md',
            id,
            disabled,
            ...props
        },
        ref
    ) => {
        const [showPassword, setShowPassword] = useState(false);
        const [isFocused, setIsFocused] = useState(false);
        const inputId = id || `input-${label?.toLowerCase().replace(/\s/g, '-')}`;
        const helperId = `${inputId}-helper`;
        const errorId = `${inputId}-error`;

        const isPassword = type === 'password';
        const inputType = isPassword && showPassword ? 'text' : type;

        // Auto-select icon based on input type
        const getDefaultIcon = () => {
            if (leftIcon) return leftIcon;
            if (type === 'email') return <AtSymbolIcon className="h-5 w-5" />;
            if (type === 'password') return <KeyIcon className="h-5 w-5" />;
            return null;
        };

        const icon = getDefaultIcon();

        return (
            <div className="w-full">
                {/* Label */}
                {label && (
                    <label
                        htmlFor={inputId}
                        className="block text-[11px] font-semibold text-slate-500 uppercase tracking-[0.2em] mb-3 font-mono"
                    >
                        {label}
                    </label>
                )}

                {/* Input wrapper */}
                <div className="relative group">
                    {/* Left icon */}
                    {icon && (
                        <span
                            className={cn(
                                "absolute left-4 top-1/2 -translate-y-1/2 text-xl font-light transition-colors",
                                isFocused ? "text-primary" : "text-slate-400"
                            )}
                        >
                            {icon}
                        </span>
                    )}

                    {/* Input field */}
                    <input
                        ref={ref}
                        id={inputId}
                        type={inputType}
                        disabled={disabled}
                        onFocus={(e) => {
                            setIsFocused(true);
                            props.onFocus?.(e);
                        }}
                        onBlur={(e) => {
                            setIsFocused(false);
                            props.onBlur?.(e);
                        }}
                        aria-invalid={error ? 'true' : 'false'}
                        aria-describedby={
                            error ? errorId : helperText ? helperId : undefined
                        }
                        className={cn(
                            // Base styles - Light theme
                            'w-full rounded-input border bg-slate-50 text-slate-900',
                            'placeholder:text-slate-400',
                            'transition-all duration-200 ease-out',
                            // Focus styles
                            'focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary focus:bg-white',
                            // Size
                            sizeStyles[size],
                            // Icon padding
                            !icon && 'pl-4',
                            (rightIcon || isPassword) && 'pr-12',
                            // States
                            error
                                ? 'border-danger focus:border-danger focus:ring-danger'
                                : success
                                    ? 'border-success focus:border-success focus:ring-success'
                                    : 'border-slate-200 hover:border-slate-300',
                            // Disabled
                            disabled && 'cursor-not-allowed opacity-50',
                            className
                        )}
                        {...props}
                    />

                    {/* Right icon or password toggle */}
                    {(rightIcon || isPassword) && (
                        <div className="absolute inset-y-0 right-0 flex items-center pr-4">
                            {isPassword ? (
                                <button
                                    type="button"
                                    onClick={() => setShowPassword(!showPassword)}
                                    className={cn(
                                        "transition-colors focus:outline-none",
                                        isFocused ? "text-primary" : "text-slate-400 hover:text-slate-600"
                                    )}
                                    aria-label={showPassword ? 'Hide password' : 'Show password'}
                                >
                                    {showPassword ? (
                                        <EyeSlashIcon className="h-5 w-5" />
                                    ) : (
                                        <EyeIcon className="h-5 w-5" />
                                    )}
                                </button>
                            ) : (
                                <span className="text-slate-400">{rightIcon}</span>
                            )}
                        </div>
                    )}
                </div>

                {/* Error message */}
                {error && (
                    <p
                        id={errorId}
                        role="alert"
                        className="mt-2 flex items-center gap-1.5 text-sm text-danger"
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
                    <p id={helperId} className="mt-2 text-sm text-slate-500">
                        {helperText}
                    </p>
                )}
            </div>
        );
    }
);

Input.displayName = 'Input';

export default Input;
