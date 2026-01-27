import React from 'react';
import { cn } from '../../utils/cn';

export interface ButtonProps
    extends React.ButtonHTMLAttributes<HTMLButtonElement> {
    variant?: 'primary' | 'secondary' | 'ghost' | 'danger';
    size?: 'sm' | 'md' | 'lg';
    isLoading?: boolean;
    leftIcon?: React.ReactNode;
    rightIcon?: React.ReactNode;
    fullWidth?: boolean;
}

const variantStyles = {
    primary: `
    bg-primary text-white border-transparent
    hover:bg-primary-dark
    shadow-button-blue hover:shadow-button-blue-hover
    active:scale-[0.98]
    disabled:opacity-50 disabled:hover:shadow-button-blue
    uppercase tracking-widest font-mono
  `,
    secondary: `
    bg-transparent text-primary border-primary
    hover:bg-primary/10
    active:bg-primary/20
    disabled:text-primary/50 disabled:border-primary/50
  `,
    ghost: `
    bg-transparent text-slate-500 border-transparent
    hover:bg-slate-100 hover:text-slate-900
    active:bg-slate-200
    disabled:text-slate-400
  `,
    danger: `
    bg-danger text-white border-transparent
    hover:bg-danger-light
    shadow-glow-danger
    active:scale-[0.98]
    disabled:opacity-50
  `,
};

const sizeStyles = {
    sm: 'px-4 py-2 text-xs gap-2 min-h-[36px]',
    md: 'px-6 py-4 text-sm gap-3 min-h-[52px]',
    lg: 'px-8 py-5 text-base gap-3 min-h-[60px]',
};

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
    (
        {
            className,
            variant = 'primary',
            size = 'md',
            isLoading = false,
            leftIcon,
            rightIcon,
            fullWidth = false,
            disabled,
            children,
            ...props
        },
        ref
    ) => {
        return (
            <button
                ref={ref}
                className={cn(
                    // Base styles
                    'inline-flex items-center justify-center font-bold',
                    'rounded-input border transition-all duration-200 ease-out',
                    'focus:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2',
                    // Variant and size
                    variantStyles[variant],
                    sizeStyles[size],
                    // Full width
                    fullWidth && 'w-full',
                    // Disabled state
                    (disabled || isLoading) && 'cursor-not-allowed',
                    className
                )}
                disabled={disabled || isLoading}
                {...props}
            >
                {isLoading ? (
                    <>
                        <LoadingSpinner className="h-5 w-5" />
                        <span>Loading...</span>
                    </>
                ) : (
                    <>
                        {leftIcon && <span className="flex-shrink-0">{leftIcon}</span>}
                        {children}
                        {rightIcon && <span className="flex-shrink-0">{rightIcon}</span>}
                    </>
                )}
            </button>
        );
    }
);

Button.displayName = 'Button';

// Loading spinner component
const LoadingSpinner = ({ className }: { className?: string }) => (
    <svg
        className={cn('animate-spin', className)}
        xmlns="http://www.w3.org/2000/svg"
        fill="none"
        viewBox="0 0 24 24"
    >
        <circle
            className="opacity-25"
            cx="12"
            cy="12"
            r="10"
            stroke="currentColor"
            strokeWidth="4"
        />
        <path
            className="opacity-75"
            fill="currentColor"
            d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
        />
    </svg>
);

export default Button;
