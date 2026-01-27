// User types
export type UserRole = 'ADMIN' | 'VIEWER' | 'HOME_USER';

export type InstituteType = 'COLLEGE' | 'SCHOOL' | 'COMPANY';

export interface User {
    id: string;
    email: string;
    name: string;
    role: UserRole;
    instituteName?: string;
    instituteCode?: string;
    createdAt: string;
}

// Auth types
export interface LoginCredentials {
    email: string;
    password: string;
}

export interface AuthResponse {
    token: string;
    user: User;
}

// Registration types
export interface InstituteAdminRegistration {
    instituteName: string;
    instituteType: InstituteType;
    location?: string;
    adminName: string;
    email: string;
    password: string;
    confirmPassword: string;
}

export interface ViewerRegistration {
    instituteCode: string;
    name: string;
    email: string;
    password: string;
    confirmPassword: string;
}

export interface HomeUserRegistration {
    name: string;
    email: string;
    password: string;
    confirmPassword: string;
    networkName?: string;
}

export interface InstituteVerification {
    valid: boolean;
    instituteName: string;
    instituteType?: string;
}

// Account type for registration flow
export type AccountType = 'institute_admin' | 'viewer' | 'home_user' | null;

// API Response types
export interface ApiResponse<T> {
    success: boolean;
    data?: T;
    message?: string;
    error?: string;
}

// Form state
export interface FormState {
    isLoading: boolean;
    error: string | null;
    success: boolean;
}
