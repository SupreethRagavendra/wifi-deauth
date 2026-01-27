import React from 'react';
import { RadioGroup as HeadlessRadioGroup } from '@headlessui/react';
import { cn } from '../../utils/cn';

export interface RadioOption {
    value: string;
    label: string;
    description?: string;
    icon?: React.ReactNode;
    disabled?: boolean;
}

export interface RadioGroupProps {
    label?: string;
    value: string;
    onChange: (value: string) => void;
    options: RadioOption[];
    error?: string;
    orientation?: 'horizontal' | 'vertical';
    className?: string;
}

export const RadioGroup: React.FC<RadioGroupProps> = ({
    label,
    value,
    onChange,
    options,
    error,
    orientation = 'vertical',
    className,
}) => {
    return (
        <HeadlessRadioGroup
            value={value}
            onChange={onChange}
            className={cn('w-full', className)}
        >
            {label && (
                <HeadlessRadioGroup.Label className="mb-3 block text-body-sm font-medium text-text-secondary">
                    {label}
                </HeadlessRadioGroup.Label>
            )}

            <div
                className={cn(
                    'gap-3',
                    orientation === 'horizontal'
                        ? 'flex flex-wrap'
                        : 'flex flex-col'
                )}
            >
                {options.map((option) => (
                    <HeadlessRadioGroup.Option
                        key={option.value}
                        value={option.value}
                        disabled={option.disabled}
                        className={({ checked, active }) =>
                            cn(
                                'relative flex cursor-pointer rounded-card border p-4',
                                'transition-all duration-focus ease-out',
                                'focus:outline-none',
                                checked
                                    ? 'border-primary bg-primary/10'
                                    : 'border-border-default bg-background-secondary hover:border-border-hover',
                                active && 'ring-4 ring-primary/15',
                                option.disabled && 'cursor-not-allowed opacity-50'
                            )
                        }
                    >
                        {({ checked }) => (
                            <div className="flex w-full items-start gap-4">
                                {/* Custom radio indicator */}
                                <div
                                    className={cn(
                                        'mt-1 flex h-5 w-5 flex-shrink-0 items-center justify-center rounded-full border-2',
                                        'transition-all duration-focus',
                                        checked
                                            ? 'border-primary bg-primary'
                                            : 'border-border-default bg-transparent'
                                    )}
                                >
                                    {checked && (
                                        <div className="h-2 w-2 rounded-full bg-white" />
                                    )}
                                </div>

                                {/* Icon (optional) */}
                                {option.icon && (
                                    <div
                                        className={cn(
                                            'flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-button',
                                            checked
                                                ? 'bg-primary text-white'
                                                : 'bg-white/5 text-text-secondary'
                                        )}
                                    >
                                        {option.icon}
                                    </div>
                                )}

                                {/* Label and description */}
                                <div className="flex-1 min-w-0">
                                    <HeadlessRadioGroup.Label
                                        as="span"
                                        className={cn(
                                            'block text-body font-medium',
                                            checked ? 'text-text-primary' : 'text-text-secondary'
                                        )}
                                    >
                                        {option.label}
                                    </HeadlessRadioGroup.Label>
                                    {option.description && (
                                        <HeadlessRadioGroup.Description
                                            as="span"
                                            className="mt-1 block text-body-sm text-text-muted"
                                        >
                                            {option.description}
                                        </HeadlessRadioGroup.Description>
                                    )}
                                </div>
                            </div>
                        )}
                    </HeadlessRadioGroup.Option>
                ))}
            </div>

            {/* Error message */}
            {error && (
                <p role="alert" className="mt-2 text-body-sm text-danger">
                    {error}
                </p>
            )}
        </HeadlessRadioGroup>
    );
};

export default RadioGroup;
