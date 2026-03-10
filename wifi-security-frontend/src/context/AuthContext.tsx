import React, {
    createContext,
    useContext,
    useState,
    useCallback,
    useMemo,
    ReactNode,
} from 'react';
import { User, UserRole } from '../types';
import { authService, getToken, getStoredUser, setStoredUser } from '../services/api';

interface AuthContextType {
    user: User | null;
    token: string | null;
    isAuthenticated: boolean;
    isLoading: boolean;
    error: string | null;
    login: (email: string, password: string) => Promise<boolean>;
    logout: () => void;
    setUser: (user: User) => void;
    updateProfile: (updatedData: Partial<User>) => void;
    clearError: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

interface AuthProviderProps {
    children: ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
    // Initialize user from localStorage if available
    const [user, setUserState] = useState<User | null>(() => getStoredUser());
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const login = useCallback(async (email: string, password: string): Promise<boolean> => {
        setIsLoading(true);
        setError(null);

        try {
            const response = await authService.login(email, password);

            if (response.success && response.data) {
                setUserState(response.data.user);
                // Persist user to localStorage
                setStoredUser(response.data.user);
                return true;
            } else {
                setError(response.error || 'Login failed');
                return false;
            }
        } catch (err) {
            const errorMessage =
                err instanceof Error ? err.message : 'An unexpected error occurred';
            setError(errorMessage);
            return false;
        } finally {
            setIsLoading(false);
        }
    }, []);

    const logout = useCallback(() => {
        authService.logout();
        setUserState(null);
        setStoredUser(null);
        setError(null);
    }, []);

    const setUser = useCallback((newUser: User) => {
        setUserState(newUser);
    }, []);

    const updateProfile = useCallback((updatedData: Partial<User>) => {
        setUserState((prevUser) => {
            if (!prevUser) return null;
            const newUser = { ...prevUser, ...updatedData };
            setStoredUser(newUser);
            return newUser;
        });
    }, []);

    const clearError = useCallback(() => {
        setError(null);
    }, []);

    const value = useMemo(
        () => ({
            user,
            token: getToken(),
            isAuthenticated: !!user && !!getToken(),
            isLoading,
            error,
            login,
            logout,
            setUser,
            updateProfile,
            clearError,
        }),
        [user, isLoading, error, login, logout, setUser, updateProfile, clearError]
    );

    return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = (): AuthContextType => {
    const context = useContext(AuthContext);
    if (context === undefined) {
        throw new Error('useAuth must be used within an AuthProvider');
    }
    return context;
};

// Helper hook to check specific roles
export const useRole = (): UserRole | null => {
    const { user } = useAuth();
    return user?.role || null;
};

// Helper hook to check if user has specific role
export const useHasRole = (role: UserRole): boolean => {
    const currentRole = useRole();
    return currentRole === role;
};

export default AuthContext;
