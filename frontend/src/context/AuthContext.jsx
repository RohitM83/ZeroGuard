import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";

import {
  getCurrentUser,
  getStoredToken,
  login as apiLogin,
  logout as apiLogout,
  signup as apiSignup,
} from "../services/api";

const AuthContext = createContext(null);

const AUTH_TOKEN_KEY = "zeroguard_token";

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  /*
   * Clear authentication information completely.
   */
  const clearAuthentication = useCallback(() => {
    localStorage.removeItem(AUTH_TOKEN_KEY);
    setUser(null);
  }, []);

  /*
   * Clear only the authentication error.
   */
  const clearAuthError = useCallback(() => {
    setError("");
  }, []);

  /*
   * Restore the currently logged-in user from the saved token.
   */
  const refreshUser = useCallback(async () => {
    const token = getStoredToken();

    if (!token) {
      setUser(null);
      return null;
    }

    try {
      const currentUser = await getCurrentUser();

      setUser(currentUser);
      setError("");

      return currentUser;
    } catch (err) {
      console.error(
        "Failed to restore authentication:",
        err
      );

      clearAuthentication();

      return null;
    }
  }, [clearAuthentication]);

  /*
   * Check authentication when the application starts.
   */
  useEffect(() => {
    let mounted = true;

    async function restoreAuthentication() {
      const token = getStoredToken();

      if (!token) {
        if (mounted) {
          setLoading(false);
        }

        return;
      }

      try {
        const currentUser = await getCurrentUser();

        if (mounted) {
          setUser(currentUser);
          setError("");
        }
      } catch (err) {
        console.error(
          "Authentication restore failed:",
          err
        );

        if (mounted) {
          clearAuthentication();
        }
      } finally {
        if (mounted) {
          setLoading(false);
        }
      }
    }

    restoreAuthentication();

    return () => {
      mounted = false;
    };
  }, [clearAuthentication]);

  /*
   * Login
   */
  const login = useCallback(
    async (username, password) => {
      setError("");

      try {
        const response = await apiLogin(
          username,
          password
        );

        if (response?.user) {
          setUser(response.user);
        } else {
          await refreshUser();
        }

        return response;
      } catch (err) {
        const message =
          err?.message ||
          "Login failed. Please check your username and password.";

        setError(message);

        throw err;
      }
    },
    [refreshUser]
  );

  /*
   * Signup
   */
  const signup = useCallback(async (payload) => {
    setError("");

    try {
      const response = await apiSignup(payload);

      /*
       * Support both possible signup responses:
       *
       * 1. Signup returns token + user
       * 2. Signup only returns success message
       */
      if (response?.token) {
        localStorage.setItem(
          AUTH_TOKEN_KEY,
          response.token
        );
      }

      if (response?.user) {
        setUser(response.user);
      }

      return response;
    } catch (err) {
      const message =
        err?.message ||
        "Signup failed. Please try again.";

      setError(message);

      throw err;
    }
  }, []);

  /*
   * Logout
   */
  const logout = useCallback(async () => {
    setError("");

    try {
      await apiLogout();
    } catch (err) {
      /*
       * Even if the backend logout request fails,
       * we still remove the local authentication.
       */
      console.error(
        "Backend logout failed:",
        err
      );
    } finally {
      clearAuthentication();
    }
  }, [clearAuthentication]);

  /*
   * Role helpers
   */
  const isAuthenticated = Boolean(user);

  /*
   * Compatibility alias.
   *
   * ProtectedRoute.jsx uses "isLoggedIn",
   * while the rest of the application can use
   * "isAuthenticated".
   */
  const isLoggedIn = isAuthenticated;

  /*
   * Admin check.
   */
  const isAdmin = user?.role === "admin";

  /*
   * Context value
   */
  const value = useMemo(
    () => ({
      user,
      loading,
      error,

      isAuthenticated,
      isLoggedIn,
      isAdmin,

      login,
      signup,
      logout,

      refreshUser,
      clearAuthError,
    }),
    [
      user,
      loading,
      error,
      isAuthenticated,
      isLoggedIn,
      isAdmin,
      login,
      signup,
      logout,
      refreshUser,
      clearAuthError,
    ]
  );

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}

/*
 * Custom authentication hook
 */
export function useAuth() {
  const context = useContext(AuthContext);

  if (!context) {
    throw new Error(
      "useAuth must be used inside an AuthProvider"
    );
  }

  return context;
}

export default AuthContext;