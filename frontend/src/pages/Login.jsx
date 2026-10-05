import React, { useState, useEffect } from 'react';
import { loginUser, registerUser, resetPassword } from '../api';

const TAGLINES = [
  "Protecting you from phishing",
  "Detecting deepfakes in real-time",
  "Monitoring network threats 24/7",
  "AI-powered threat intelligence"
];

function Login({ onLogin }) {
  const [activeTab, setActiveTab] = useState('signin');
  const [taglineIndex, setTaglineIndex] = useState(0);
  const [fade, setFade] = useState(true);

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [oldPassword, setOldPassword] = useState('');
  const [rememberMe, setRememberMe] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  useEffect(() => {
    const intervalId = setInterval(() => {
      setFade(false);
      setTimeout(() => {
        setTaglineIndex((prev) => (prev + 1) % TAGLINES.length);
        setFade(true);
      }, 500);
    }, 3000);
    return () => clearInterval(intervalId);
  }, []);

  const handleTabSwitch = (tab) => {
    setActiveTab(tab);
    setUsername('');
    setPassword('');
    setConfirmPassword('');
    setOldPassword('');
    setError('');
    setSuccess('');
    setShowPassword(false);
    setShowConfirmPassword(false);
  };

  const calculatePasswordStrength = (pass) => {
    let score = 0;
    if (pass.length > 5) score += 1;
    if (pass.length > 8) score += 1;
    if (/[A-Z]/.test(pass)) score += 1;
    if (/[0-9]/.test(pass)) score += 1;
    if (/[^A-Za-z0-9]/.test(pass)) score += 1;

    if (pass.length === 0) return { width: '0%', color: 'bg-transparent' };
    if (score <= 2) return { width: '33%', color: 'bg-red-500' };
    if (score <= 4) return { width: '66%', color: 'bg-yellow-500' };
    return { width: '100%', color: 'bg-green-500' };
  };

  const handleSignIn = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    
    if (username.length < 3) {
      setError('Username must be at least 3 characters.');
      return;
    }
    if (password.length < 6) {
      setError('Password must be at least 6 characters.');
      return;
    }

    setLoading(true);
    try {
      const result = await loginUser(username, password);
      if (result.success) {
        onLogin(username);
      } else {
        setError(result.message || 'Login failed.');
      }
    } catch (err) {
      setError('An error occurred during login.');
    } finally {
      setLoading(false);
    }
  };

  const handleSignUp = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    if (username.length < 3) {
      setError('Username must be at least 3 characters.');
      return;
    }
    if (password.length < 6) {
      setError('Password must be at least 6 characters.');
      return;
    }
    if (password !== confirmPassword) {
      setError('Passwords do not match.');
      return;
    }

    setLoading(true);
    try {
      const result = await registerUser(username, password);
      if (result.success) {
        setSuccess('Registration successful! Please sign in.');
        setTimeout(() => handleTabSwitch('signin'), 1500);
      } else {
        setError(result.message || 'Registration failed.');
      }
    } catch (err) {
      setError('An error occurred during registration.');
    } finally {
      setLoading(false);
    }
  };

  const handleResetPassword = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    if (username.length < 3) {
      setError('Username must be at least 3 characters.');
      return;
    }
    if (oldPassword.length < 1) {
      setError('Please enter your current password.');
      return;
    }
    if (password.length < 6) {
      setError('New password must be at least 6 characters.');
      return;
    }
    if (password !== confirmPassword) {
      setError('New passwords do not match.');
      return;
    }

    setLoading(true);
    try {
      const result = await resetPassword(username, oldPassword, password);
      if (result.success) {
        setSuccess('Password reset successful! Please sign in with your new password.');
        setTimeout(() => handleTabSwitch('signin'), 2000);
      } else {
        setError(result.message || 'Password reset failed.');
      }
    } catch (err) {
      setError('An error occurred during password reset.');
    } finally {
      setLoading(false);
    }
  };

  const strength = calculatePasswordStrength(password);

  return (
    <div className="min-h-screen flex items-center justify-center p-4 bg-gradient-to-br from-gray-950 via-gray-900 to-blue-950 text-white">
      <div className="w-full max-w-md bg-gray-900 border border-gray-800 rounded-2xl shadow-[0_0_20px_rgba(37,99,235,0.15)] overflow-hidden flex flex-col">
        {/* Header Section */}
        <div className="pt-8 px-8 pb-6 flex flex-col items-center border-b border-gray-800">
          <div className="text-4xl mb-2">🛡️</div>
          <h1 className="text-2xl font-bold mb-1">CyberGuard</h1>
          <p className="text-sm text-gray-400 text-center mb-4">AI-Powered Cyber Threat Detection Platform</p>
          <div className="h-6 overflow-hidden">
            <p className={`text-xs text-blue-400 transition-opacity duration-500 ease-in-out ${fade ? 'opacity-100' : 'opacity-0'}`}>
              {TAGLINES[taglineIndex]}
            </p>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex bg-gray-950/50">
          <button
            onClick={() => handleTabSwitch('signin')}
            className={`flex-1 py-3 text-sm font-semibold transition-colors ${activeTab === 'signin' ? 'text-blue-500 border-b-2 border-blue-500' : 'text-gray-500 hover:text-gray-300'}`}
          >
            Sign In
          </button>
          <button
            onClick={() => handleTabSwitch('signup')}
            className={`flex-1 py-3 text-sm font-semibold transition-colors ${activeTab === 'signup' ? 'text-blue-500 border-b-2 border-blue-500' : 'text-gray-500 hover:text-gray-300'}`}
          >
            Sign Up
          </button>
        </div>

        {/* Form Section */}
        <div className="p-8 flex-grow">
          {error && (
            <div className="mb-4 p-3 bg-red-900/50 border border-red-500 text-red-200 text-sm rounded-lg">
              {error}
            </div>
          )}
          {success && (
            <div className="mb-4 p-3 bg-green-900/50 border border-green-500 text-green-200 text-sm rounded-lg">
              {success}
            </div>
          )}

          {activeTab === 'signin' && (
            <form onSubmit={handleSignIn} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-gray-400 mb-1">Username</label>
                <div className="relative">
                  <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400">👤</span>
                  <input type="text" value={username} onChange={(e) => setUsername(e.target.value)} className="w-full pl-10 pr-4 py-2 bg-gray-950 border border-gray-800 rounded-lg focus:outline-none focus:border-blue-500 text-sm" placeholder="Enter your username" />
                </div>
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-400 mb-1">Password</label>
                <div className="relative">
                  <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400">🔒</span>
                  <input type={showPassword ? 'text' : 'password'} value={password} onChange={(e) => setPassword(e.target.value)} className="w-full pl-10 pr-10 py-2 bg-gray-950 border border-gray-800 rounded-lg focus:outline-none focus:border-blue-500 text-sm" placeholder="Enter your password" />
                  <button type="button" onClick={() => setShowPassword(!showPassword)} className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-200 text-xs">{showPassword ? 'Hide' : 'Show'}</button>
                </div>
              </div>
              <div className="flex items-center justify-between text-xs">
                <label className="flex items-center space-x-2 cursor-pointer">
                  <input type="checkbox" checked={rememberMe} onChange={(e) => setRememberMe(e.target.checked)} className="w-4 h-4 rounded border-gray-700 bg-gray-950 text-blue-500 focus:ring-blue-500" />
                  <span className="text-gray-400">Remember me</span>
                </label>
                <button type="button" onClick={() => handleTabSwitch('reset')} className="text-blue-400 hover:text-blue-300">Forgot password?</button>
              </div>
              <button type="submit" disabled={loading} className="w-full py-2.5 mt-2 bg-gradient-to-r from-blue-600 to-blue-500 hover:from-blue-500 hover:to-blue-400 text-white rounded-lg font-medium text-sm transition-all shadow-[0_0_15px_rgba(37,99,235,0.3)] disabled:opacity-70 disabled:cursor-not-allowed flex items-center justify-center">
                {loading ? (<svg className="animate-spin h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>) : 'Sign In'}
              </button>
            </form>
          )}

          {activeTab === 'signup' && (
            <form onSubmit={handleSignUp} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-gray-400 mb-1">Username</label>
                <div className="relative">
                  <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400">👤</span>
                  <input type="text" value={username} onChange={(e) => setUsername(e.target.value)} className="w-full pl-10 pr-4 py-2 bg-gray-950 border border-gray-800 rounded-lg focus:outline-none focus:border-blue-500 text-sm" placeholder="Choose a username" />
                </div>
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-400 mb-1">Password</label>
                <div className="relative">
                  <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400">🔒</span>
                  <input type={showPassword ? 'text' : 'password'} value={password} onChange={(e) => setPassword(e.target.value)} className="w-full pl-10 pr-10 py-2 bg-gray-950 border border-gray-800 rounded-lg focus:outline-none focus:border-blue-500 text-sm" placeholder="Create a password" />
                  <button type="button" onClick={() => setShowPassword(!showPassword)} className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-200 text-xs">{showPassword ? 'Hide' : 'Show'}</button>
                </div>
                <div className="mt-2 h-1.5 w-full bg-gray-800 rounded-full overflow-hidden flex">
                  <div className={`h-full transition-all duration-300 ${strength.color}`} style={{ width: strength.width }}></div>
                </div>
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-400 mb-1">Confirm Password</label>
                <div className="relative">
                  <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400">🔒</span>
                  <input type={showConfirmPassword ? 'text' : 'password'} value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} className="w-full pl-10 pr-10 py-2 bg-gray-950 border border-gray-800 rounded-lg focus:outline-none focus:border-blue-500 text-sm" placeholder="Confirm password" />
                  <button type="button" onClick={() => setShowConfirmPassword(!showConfirmPassword)} className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-200 text-xs">{showConfirmPassword ? 'Hide' : 'Show'}</button>
                </div>
              </div>
              <button type="submit" disabled={loading} className="w-full py-2.5 mt-2 bg-gradient-to-r from-blue-600 to-blue-500 hover:from-blue-500 hover:to-blue-400 text-white rounded-lg font-medium text-sm transition-all shadow-[0_0_15px_rgba(37,99,235,0.3)] disabled:opacity-70 disabled:cursor-not-allowed flex items-center justify-center">
                {loading ? (<svg className="animate-spin h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>) : 'Sign Up'}
              </button>
            </form>
          )}

          {activeTab === 'reset' && (
            <form onSubmit={handleResetPassword} className="space-y-4">
              <div className="text-center mb-2">
                <span className="text-2xl">🔑</span>
                <h3 className="text-sm font-semibold text-gray-300 mt-1">Reset Your Password</h3>
                <p className="text-xs text-gray-500">Enter your username and current password to set a new one</p>
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-400 mb-1">Username</label>
                <div className="relative">
                  <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400">👤</span>
                  <input type="text" value={username} onChange={(e) => setUsername(e.target.value)} className="w-full pl-10 pr-4 py-2 bg-gray-950 border border-gray-800 rounded-lg focus:outline-none focus:border-blue-500 text-sm" placeholder="Your username" />
                </div>
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-400 mb-1">Current Password</label>
                <div className="relative">
                  <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400">🔒</span>
                  <input type="password" value={oldPassword} onChange={(e) => setOldPassword(e.target.value)} className="w-full pl-10 pr-4 py-2 bg-gray-950 border border-gray-800 rounded-lg focus:outline-none focus:border-blue-500 text-sm" placeholder="Enter current password" />
                </div>
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-400 mb-1">New Password</label>
                <div className="relative">
                  <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400">🔒</span>
                  <input type={showPassword ? 'text' : 'password'} value={password} onChange={(e) => setPassword(e.target.value)} className="w-full pl-10 pr-10 py-2 bg-gray-950 border border-gray-800 rounded-lg focus:outline-none focus:border-blue-500 text-sm" placeholder="Enter new password" />
                  <button type="button" onClick={() => setShowPassword(!showPassword)} className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-200 text-xs">{showPassword ? 'Hide' : 'Show'}</button>
                </div>
                <div className="mt-2 h-1.5 w-full bg-gray-800 rounded-full overflow-hidden flex">
                  <div className={`h-full transition-all duration-300 ${strength.color}`} style={{ width: strength.width }}></div>
                </div>
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-400 mb-1">Confirm New Password</label>
                <div className="relative">
                  <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400">🔒</span>
                  <input type={showConfirmPassword ? 'text' : 'password'} value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} className="w-full pl-10 pr-10 py-2 bg-gray-950 border border-gray-800 rounded-lg focus:outline-none focus:border-blue-500 text-sm" placeholder="Confirm new password" />
                  <button type="button" onClick={() => setShowConfirmPassword(!showConfirmPassword)} className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-200 text-xs">{showConfirmPassword ? 'Hide' : 'Show'}</button>
                </div>
              </div>
              <button type="submit" disabled={loading} className="w-full py-2.5 mt-2 bg-gradient-to-r from-blue-600 to-blue-500 hover:from-blue-500 hover:to-blue-400 text-white rounded-lg font-medium text-sm transition-all shadow-[0_0_15px_rgba(37,99,235,0.3)] disabled:opacity-70 disabled:cursor-not-allowed flex items-center justify-center">
                {loading ? (<svg className="animate-spin h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>) : 'Reset Password'}
              </button>
              <p className="text-center text-xs text-gray-500">
                <button type="button" onClick={() => handleTabSwitch('signin')} className="text-blue-400 hover:text-blue-300">← Back to Sign In</button>
              </p>
            </form>
          )}
        </div>

        {/* Footer */}
        <div className="py-4 bg-gray-950 flex flex-col items-center justify-center border-t border-gray-800">
          <div className="flex items-center space-x-1 text-gray-500 text-xs">
            <span>🛡️</span>
            <span>Protected by CyberGuard AI</span>
          </div>
          <span className="text-[10px] text-gray-600 mt-1">v2.0</span>
        </div>
      </div>
    </div>
  );
}

export default Login;