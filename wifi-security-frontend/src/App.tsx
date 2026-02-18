import React from 'react';
import {
  BrowserRouter,
  Routes,
  Route,
  Navigate,
  useLocation,
} from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import {
  Register,
  Login,
  AdminDashboard,
  ViewerDashboard,
  HomeDashboard,
  DetectionMonitor,
} from './pages';
import './index.css';

// Protected Route component
interface ProtectedRouteProps {
  children: React.ReactNode;
  allowedRoles?: string[];
}

const ProtectedRoute: React.FC<ProtectedRouteProps> = ({
  children,
  allowedRoles,
}) => {
  const { isAuthenticated, user } = useAuth();
  const location = useLocation();

  if (!isAuthenticated) {
    // Redirect to login, preserving intended destination
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  // Check role if specified
  if (allowedRoles && user && !allowedRoles.includes(user.role)) {
    // Redirect to appropriate dashboard based on role
    const redirectPath = getDefaultDashboard(user.role);
    return <Navigate to={redirectPath} replace />;
  }

  return <>{children}</>;
};

// Get default dashboard based on role
const getDefaultDashboard = (role: string): string => {
  switch (role) {
    case 'ADMIN':
      return '/admin/dashboard';
    case 'VIEWER':
      return '/viewer/dashboard';
    case 'HOME_USER':
      return '/home/dashboard';
    default:
      return '/login';
  }
};

// Home redirect component
const HomeRedirect: React.FC = () => {
  const { isAuthenticated, user } = useAuth();

  if (isAuthenticated && user) {
    return <Navigate to={getDefaultDashboard(user.role)} replace />;
  }

  return <Navigate to="/login" replace />;
};

// App Routes
const AppRoutes: React.FC = () => {
  return (
    <Routes>
      {/* Public routes */}
      <Route path="/register" element={<Register />} />
      <Route path="/login" element={<Login />} />

      {/* Protected routes - Admin */}
      <Route
        path="/admin/dashboard"
        element={
          <ProtectedRoute allowedRoles={['ADMIN']}>
            <AdminDashboard />
          </ProtectedRoute>
        }
      />

      {/* Protected routes - Viewer */}
      <Route
        path="/viewer/dashboard"
        element={
          <ProtectedRoute allowedRoles={['VIEWER']}>
            <ViewerDashboard />
          </ProtectedRoute>
        }
      />

      {/* Protected routes - Home User */}
      <Route
        path="/home/dashboard"
        element={
          <ProtectedRoute allowedRoles={['HOME_USER']}>
            <HomeDashboard />
          </ProtectedRoute>
        }
      />

      {/* Protected routes - Detection Monitor (accessible to all authenticated users) */}
      <Route
        path="/detection-monitor"
        element={
          <ProtectedRoute>
            <DetectionMonitor />
          </ProtectedRoute>
        }
      />

      {/* Home route - redirect based on auth status */}
      <Route path="/" element={<HomeRedirect />} />

      {/* Catch all - redirect to home */}
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
};

// Main App component
const App: React.FC = () => {
  return (
    <BrowserRouter>
      <AuthProvider>
        <AppRoutes />
      </AuthProvider>
    </BrowserRouter>
  );
};

export default App;
