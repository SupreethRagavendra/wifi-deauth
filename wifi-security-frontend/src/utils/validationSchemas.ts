import { z } from 'zod';

// Password validation rules
const passwordSchema = z
    .string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[0-9]/, 'Password must contain at least one number');

// Email validation
const emailSchema = z
    .string()
    .min(1, 'Email is required')
    .email('Please enter a valid email address');

// Name validation
const nameSchema = z
    .string()
    .min(2, 'Name must be at least 2 characters')
    .max(100, 'Name must be less than 100 characters');

// Institute Admin Registration Schema
export const instituteAdminSchema = z
    .object({
        instituteName: z
            .string()
            .min(3, 'Institute name must be at least 3 characters')
            .max(255, 'Institute name must be less than 255 characters'),
        instituteType: z.enum(['COLLEGE', 'SCHOOL', 'COMPANY'], {
            required_error: 'Please select an institute type',
        }),
        location: z.string().optional(),
        adminName: z
            .string()
            .min(2, 'Admin name must be at least 2 characters')
            .max(100, 'Admin name must be less than 100 characters'),
        email: emailSchema,
        password: passwordSchema,
        confirmPassword: z.string().min(1, 'Please confirm your password'),
    })
    .refine((data) => data.password === data.confirmPassword, {
        message: 'Passwords do not match',
        path: ['confirmPassword'],
    });

// Viewer Registration Schema
export const viewerSchema = z
    .object({
        instituteCode: z
            .string()
            .min(1, 'Institute code is required')
            .regex(
                /^[A-Z0-9]+$/,
                'Institute code must contain only uppercase letters and numbers'
            ),
        name: nameSchema,
        email: emailSchema,
        password: passwordSchema,
        confirmPassword: z.string().min(1, 'Please confirm your password'),
    })
    .refine((data) => data.password === data.confirmPassword, {
        message: 'Passwords do not match',
        path: ['confirmPassword'],
    });

// Home User Registration Schema
export const homeUserSchema = z
    .object({
        name: nameSchema,
        email: emailSchema,
        password: passwordSchema,
        confirmPassword: z.string().min(1, 'Please confirm your password'),
        networkName: z.string().optional(),
    })
    .refine((data) => data.password === data.confirmPassword, {
        message: 'Passwords do not match',
        path: ['confirmPassword'],
    });

// Login Schema (no password strength validation on login)
export const loginSchema = z.object({
    email: emailSchema,
    password: z.string().min(1, 'Password is required'),
});

// Institute Code Verification Schema
export const instituteCodeSchema = z.object({
    code: z
        .string()
        .min(1, 'Institute code is required')
        .regex(
            /^[A-Z0-9]+$/,
            'Institute code must contain only uppercase letters and numbers'
        ),
});

// Export TypeScript types inferred from schemas
export type InstituteAdminFormData = z.infer<typeof instituteAdminSchema>;
export type ViewerFormData = z.infer<typeof viewerSchema>;
export type HomeUserFormData = z.infer<typeof homeUserSchema>;
export type LoginFormData = z.infer<typeof loginSchema>;
export type InstituteCodeFormData = z.infer<typeof instituteCodeSchema>;

// Password strength calculator
export function calculatePasswordStrength(password: string): {
    score: number;
    label: string;
    color: string;
} {
    let score = 0;

    if (password.length >= 8) score++;
    if (password.length >= 12) score++;
    if (/[a-z]/.test(password)) score++;
    if (/[A-Z]/.test(password)) score++;
    if (/[0-9]/.test(password)) score++;
    if (/[^a-zA-Z0-9]/.test(password)) score++;

    if (score <= 2) {
        return { score: 25, label: 'Weak', color: 'bg-danger' };
    } else if (score <= 4) {
        return { score: 50, label: 'Fair', color: 'bg-warning' };
    } else if (score <= 5) {
        return { score: 75, label: 'Good', color: 'bg-info' };
    } else {
        return { score: 100, label: 'Strong', color: 'bg-success' };
    }
}
