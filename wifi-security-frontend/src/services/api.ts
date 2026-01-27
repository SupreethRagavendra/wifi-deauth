import axios, { AxiosInstance, AxiosError } from 'axios';
import {
    AuthResponse,
    User,
    ApiResponse,
    InstituteVerification,
} from '../types';
import {
    InstituteAdminFormData,
    ViewerFormData,
    HomeUserFormData,
} from '../utils/validationSchemas';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8080/api';

// In-memory token storage (NOT localStorage per requirements)
let authToken: string | null = null;

export const getToken = (): string | null => authToken;
export const setToken = (token: string | null): void => {
    authToken = token;
};
export const clearToken = (): void => {
    authToken = null;
};

// Create axios instance
const api: AxiosInstance = axios.create({
    baseURL: API_URL,
    headers: {
        'Content-Type': 'application/json',
    },
    timeout: 10000,
});

// Request interceptor to add auth token
api.interceptors.request.use(
    (config) => {
        const token = getToken();
        if (token) {
            config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
    },
    (error) => Promise.reject(error)
);

// Response interceptor for error handling
api.interceptors.response.use(
    (response) => response,
    (error: AxiosError<{ message?: string }>) => {
        const message =
            error.response?.data?.message ||
            error.message ||
            'An unexpected error occurred';

        // Handle 401 Unauthorized
        if (error.response?.status === 401) {
            clearToken();
            // Could trigger a logout or redirect here
        }

        return Promise.reject(new Error(message));
    }
);

// Auth Service
export const authService = {
    // Register Institute Admin
    async registerAdmin(
        data: InstituteAdminFormData
    ): Promise<ApiResponse<{ user: User; token: string; instituteCode: string }>> {
        try {
            const response = await api.post('/auth/register/admin', {
                instituteName: data.instituteName,
                instituteType: data.instituteType,
                location: data.location,
                adminName: data.adminName,
                email: data.email,
                password: data.password,
            });

            // Backend returns flat structure, transform to match expected type
            const {
                token,
                userId,
                email: userEmail,
                name,
                role,
                instituteName,
                instituteCode,
                instituteType
            } = response.data;

            setToken(token);

            // Map to User type
            const user: User = {
                id: userId,
                email: userEmail,
                name,
                role,
                instituteName,
                instituteCode,
                createdAt: new Date().toISOString(),
            };

            return {
                success: true,
                data: { user, token, instituteCode },
            };
        } catch (error) {
            return {
                success: false,
                error: error instanceof Error ? error.message : 'Registration failed',
            };
        }
    },

    // Register Viewer
    async registerViewer(
        data: ViewerFormData
    ): Promise<ApiResponse<AuthResponse>> {
        try {
            const response = await api.post('/auth/register/viewer', {
                instituteCode: data.instituteCode,
                name: data.name,
                email: data.email,
                password: data.password,
            });

            // Backend returns flat structure, transform to match AuthResponse type
            const {
                token,
                userId,
                email: userEmail,
                name,
                role,
                instituteName,
                instituteCode,
                instituteType
            } = response.data;

            setToken(token);

            // Map to User type
            const user: User = {
                id: userId,
                email: userEmail,
                name,
                role,
                instituteName,
                instituteCode,
                createdAt: new Date().toISOString(),
            };

            return {
                success: true,
                data: { token, user },
            };
        } catch (error) {
            return {
                success: false,
                error: error instanceof Error ? error.message : 'Registration failed',
            };
        }
    },

    // Register Home User
    async registerHome(
        data: HomeUserFormData
    ): Promise<ApiResponse<AuthResponse>> {
        try {
            const response = await api.post('/auth/register/home', {
                name: data.name,
                email: data.email,
                password: data.password,
                networkName: data.networkName,
            });

            // Backend returns flat structure, transform to match AuthResponse type
            const {
                token,
                userId,
                email: userEmail,
                name,
                role,
                instituteName,
                instituteCode,
                instituteType
            } = response.data;

            setToken(token);

            // Map to User type
            const user: User = {
                id: userId,
                email: userEmail,
                name,
                role,
                instituteName,
                instituteCode,
                createdAt: new Date().toISOString(),
            };

            return {
                success: true,
                data: { token, user },
            };
        } catch (error) {
            return {
                success: false,
                error: error instanceof Error ? error.message : 'Registration failed',
            };
        }
    },

    // Login
    async login(email: string, password: string): Promise<ApiResponse<AuthResponse>> {
        try {
            const response = await api.post('/auth/login', { email, password });

            // Backend returns flat structure, transform to match AuthResponse type
            const {
                token,
                userId,
                email: userEmail,
                name,
                role,
                instituteName,
                instituteCode,
                instituteType
            } = response.data;

            setToken(token);

            // Map to User type
            const user: User = {
                id: userId,
                email: userEmail,
                name,
                role,
                instituteName,
                instituteCode,
                createdAt: new Date().toISOString(), // Backend doesn't return this, using current time
            };

            return {
                success: true,
                data: { token, user },
            };
        } catch (error) {
            return {
                success: false,
                error: error instanceof Error ? error.message : 'Login failed',
            };
        }
    },

    // Verify Institute Code
    async verifyInstituteCode(
        code: string
    ): Promise<ApiResponse<InstituteVerification>> {
        try {
            const response = await api.post('/auth/verify-institute-code', {
                instituteCode: code,
            });
            return {
                success: true,
                data: response.data,
            };
        } catch (error) {
            return {
                success: false,
                error: error instanceof Error ? error.message : 'Verification failed',
            };
        }
    },

    // Logout
    logout(): void {
        clearToken();
    },

    // Get current user (for session restoration)
    async getCurrentUser(): Promise<ApiResponse<User>> {
        try {
            const response = await api.get('/auth/me');
            return {
                success: true,
                data: response.data,
            };
        } catch (error) {
            return {
                success: false,
                error: error instanceof Error ? error.message : 'Failed to get user',
            };
        }
    },
};

export default api;
