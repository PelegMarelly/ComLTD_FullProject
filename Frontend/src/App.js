import React, { useEffect, useState } from 'react';
import { Route, Routes, Navigate } from 'react-router-dom'; // Removed unused useLocation
import Home from './pages/Home';
import About from './pages/About';
import DataPlans from './pages/DataPlans';
import Contact from './pages/Contact';
import Login from './pages/Login';
import Register from './pages/Register';
import ForgotPassword from './pages/ForgotPassword';
import AddCustomer from './pages/AddCustomer';
import SearchCustomer from './pages/SearchCustomer';
import UserProfile from './pages/UserProfile';
import ChangePassword from './pages/ResetPassword';
import ModalLoader from './components/ModalLoader';
import PageNotFound from './pages/404Page.js';
import SetNewPassScreen from './pages/SetNewPass.js';
import { useUser } from './context/UserContext';
import { fetchUserData, logoutUser } from './services/api.js';

function App() {
  // User context for managing global user data
  const { userData, setUserData } = useUser();

  // State to manage the loading spinner
  const [isLoading, setIsLoading] = useState(false);

  // Fetch user data on app load if token exists
  useEffect(() => {
    const token = localStorage.getItem('userToken');
    if (token && !userData) {
      setIsLoading(true);
      fetchUserData(token)
        .then((data) => setUserData({ ...data, token }))
        .catch((err) => {
          console.error('Failed to fetch user data:', err);
          localStorage.removeItem('userToken');
          setUserData(null);
        })
        .finally(() => setIsLoading(false));
    }
  }, [setUserData, userData]);

  // Handle user login and save token
  const handleLogin = (token) => {
    localStorage.setItem('userToken', token);
    setIsLoading(true);
    fetchUserData(token)
      .then((data) => setUserData({ ...data, token }))
      .catch((err) => console.error('Failed to fetch user data after login:', err))
      .finally(() => setIsLoading(false));
  };

  // Handle user logout and clear token
  const handleLogout = async () => {
    const token = localStorage.getItem('userToken');
    if (!token) {
      console.error('No token found for logout.');
      return;
    }

    try {
      await logoutUser(token);
      console.log('User logged out successfully.');
    } catch (error) {
      console.error('Logout failed:', error);
    } finally {
      setUserData(null);
      localStorage.removeItem('userToken');
      window.location.href = '/login'; // Redirect to login page after logout
    }
  };

  // Protected route wrapper to manage access control
  const ProtectedRoute = ({ element }) => {
    if (isLoading) {
      return <ModalLoader />; // Show loader while fetching user data
    }

    if (!userData) {
      const token = localStorage.getItem('userToken');
      if (token) {
        return <ModalLoader />; // Show loader if token exists but user data isn't loaded yet
      }
      return <Navigate to="/login" />; // Redirect to login if user isn't authenticated
    }

    return element; // Render the protected element if user is authenticated
  };

  return (
    <>
      <Routes>
        {/* Public Routes */}
        <Route path="/login" element={<Login onLogin={handleLogin} />} />
        <Route path="/register" element={<Register />} />
        <Route path="/forgot-password" element={<ForgotPassword />} />
        <Route path="/insert-token-and-pass" element={<SetNewPassScreen />} />

        {/* Protected Routes */}
        <Route path="/" element={<ProtectedRoute element={<Home onLogout={handleLogout} />} />} />
        <Route path="/about" element={<ProtectedRoute element={<About onLogout={handleLogout} />} />} />
        <Route path="/data-plans" element={<ProtectedRoute element={<DataPlans onLogout={handleLogout} />} />} />
        <Route path="/contact" element={<ProtectedRoute element={<Contact onLogout={handleLogout} />} />} />
        <Route path="/customers/new" element={<ProtectedRoute element={<AddCustomer onLogout={handleLogout} />} />} />
        <Route path="/customers/search" element={<ProtectedRoute element={<SearchCustomer onLogout={handleLogout} />} />} />
        <Route path="/account/profile" element={<ProtectedRoute element={<UserProfile onLogout={handleLogout} />} />} />
        <Route path="/account/change-password" element={<ProtectedRoute element={<ChangePassword onLogout={handleLogout} />} />} />

        {/* Fallback Route */}
        <Route path="*" element={<PageNotFound />} />
      </Routes>
    </>
  );
}

export default App;
