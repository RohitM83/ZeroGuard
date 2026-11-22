import {
  BrowserRouter,
  Routes,
  Route,
  Navigate,
} from "react-router-dom";

// Authentication
import { AuthProvider } from "./context/AuthContext";
import ProtectedRoute from "./components/auth/ProtectedRoute";

// Layout
import Layout from "./components/layout/Layout";

// Authentication pages
import Login from "./pages/Login";
import Signup from "./pages/Signup";

// Application pages
import Dashboard from "./pages/Dashboard";
import Devices from "./pages/Devices";
import NetworkActivity from "./pages/NetworkActivity";
import ThreatDetection from "./pages/ThreatDetection";
import Incidents from "./pages/Incidents";
import ResponseActions from "./pages/ResponseActions";
import Reports from "./pages/Reports";
import Settings from "./pages/Settings";
import UserManagement from "./pages/UserManagement";

function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>

          {/* ==================================================
              PUBLIC AUTHENTICATION ROUTES
              ================================================== */}

          <Route
            path="/login"
            element={<Login />}
          />

          <Route
            path="/signup"
            element={<Signup />}
          />

          {/* ==================================================
              PROTECTED APPLICATION
              ================================================== */}

          <Route
            path="/"
            element={
              <ProtectedRoute>
                <Layout />
              </ProtectedRoute>
            }
          >

            {/* ==================================================
                DEFAULT DASHBOARD
                ================================================== */}

            <Route
              index
              element={<Dashboard />}
            />

            {/* ==================================================
                USER + ADMIN PAGES
                ================================================== */}

            <Route
              path="devices"
              element={<Devices />}
            />

            <Route
              path="network"
              element={<NetworkActivity />}
            />

            <Route
              path="threats"
              element={<ThreatDetection />}
            />

            <Route
              path="reports"
              element={<Reports />}
            />

            {/* ==================================================
                ADMIN ONLY PAGES
                ================================================== */}

            <Route
              path="incidents"
              element={
                <ProtectedRoute adminOnly>
                  <Incidents />
                </ProtectedRoute>
              }
            />

            <Route
              path="response"
              element={
                <ProtectedRoute adminOnly>
                  <ResponseActions />
                </ProtectedRoute>
              }
            />

            <Route
              path="settings"
              element={
                <ProtectedRoute adminOnly>
                  <Settings />
                </ProtectedRoute>
              }
            />

            <Route
              path="users"
              element={
                <ProtectedRoute adminOnly>
                  <UserManagement />
                </ProtectedRoute>
              }
            />

          </Route>

          {/* ==================================================
              UNKNOWN URL
              ================================================== */}

          <Route
            path="*"
            element={
              <Navigate
                to="/"
                replace
              />
            }
          />

        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}

export default App;