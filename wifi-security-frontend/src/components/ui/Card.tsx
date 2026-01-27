import React from 'react';
import { cn } from '../../utils/cn';

export interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
    variant?: 'default' | 'bordered' | 'elevated';
    hoverable?: boolean;
    padding?: 'none' | 'sm' | 'md' | 'lg';
}

const variantStyles = {
    default: 'bg-background-secondary border border-border-default',
    bordered: 'bg-transparent border-2 border-border-default',
    elevated:
        'bg-background-secondary border border-border-default shadow-md',
};

const paddingStyles = {
    none: 'p-0',
    sm: 'p-4',
    md: 'p-6',
    lg: 'p-8',
};

export const Card = React.forwardRef<HTMLDivElement, CardProps>(
    (
        {
            className,
            variant = 'default',
            hoverable = false,
            padding = 'md',
            children,
            ...props
        },
        ref
    ) => {
        return (
            <div
                ref={ref}
                className={cn(
                    'rounded-card transition-all duration-hover',
                    variantStyles[variant],
                    paddingStyles[padding],
                    hoverable && [
                        'cursor-pointer',
                        'hover:border-primary hover:shadow-card-hover hover:-translate-y-1',
                    ],
                    className
                )}
                {...props}
            >
                {children}
            </div>
        );
    }
);

Card.displayName = 'Card';

// Card Header component
export const CardHeader = React.forwardRef<
    HTMLDivElement,
    React.HTMLAttributes<HTMLDivElement>
>(({ className, children, ...props }, ref) => (
    <div
        ref={ref}
        className={cn('mb-4 flex items-center justify-between', className)}
        {...props}
    >
        {children}
    </div>
));

CardHeader.displayName = 'CardHeader';

// Card Title component
export const CardTitle = React.forwardRef<
    HTMLHeadingElement,
    React.HTMLAttributes<HTMLHeadingElement>
>(({ className, children, ...props }, ref) => (
    <h3 ref={ref} className={cn('text-h3 text-text-primary', className)} {...props}>
        {children}
    </h3>
));

CardTitle.displayName = 'CardTitle';

// Card Description component
export const CardDescription = React.forwardRef<
    HTMLParagraphElement,
    React.HTMLAttributes<HTMLParagraphElement>
>(({ className, children, ...props }, ref) => (
    <p
        ref={ref}
        className={cn('text-body text-text-secondary', className)}
        {...props}
    >
        {children}
    </p>
));

CardDescription.displayName = 'CardDescription';

// Card Content component
export const CardContent = React.forwardRef<
    HTMLDivElement,
    React.HTMLAttributes<HTMLDivElement>
>(({ className, children, ...props }, ref) => (
    <div ref={ref} className={cn('', className)} {...props}>
        {children}
    </div>
));

CardContent.displayName = 'CardContent';

// Card Footer component
export const CardFooter = React.forwardRef<
    HTMLDivElement,
    React.HTMLAttributes<HTMLDivElement>
>(({ className, children, ...props }, ref) => (
    <div
        ref={ref}
        className={cn('mt-6 flex items-center gap-4', className)}
        {...props}
    >
        {children}
    </div>
));

CardFooter.displayName = 'CardFooter';

export default Card;
