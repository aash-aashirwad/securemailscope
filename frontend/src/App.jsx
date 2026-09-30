import { BrowserRouter, Routes, Route, Navigate, Outlet, useLocation } from 'react-router-dom'
import { AuthProvider, useAuth } from './context/AuthContext'
import Sidebar from './components/Sidebar'
import Login from './pages/Login'
import Register from './pages/Register'
import Dashboard from './pages/Dashboard'
import UploadPage from './pages/UploadPage'
import CasesPage from './pages/CasesPage'
import CaseDetail from './pages/CaseDetail'
import AllFindings from './pages/AllFindings'
import ComplianceView from './pages/ComplianceView'
import AdminUsers from './pages/AdminUsers'
import AuditLogs from './pages/AuditLogs'
import AccountSecurity from './pages/AccountSecurity'
import TraceabilityMatrix from './pages/TraceabilityMatrix'
import PerformanceBenchmark from './pages/PerformanceBenchmark'
import RolesAccess from './pages/RolesAccess'

function AppLayout() {
  return (
    <div className="flex min-h-screen bg-ink-950">
      <Sidebar />
      <main className="flex-1 min-w-0">
        <Outlet />
      </main>
    </div>
  )
}

function ProtectedRoute({ roles }) {
  const { user, loading } = useAuth()
  const location = useLocation()
  if (loading) return <div className="min-h-screen flex items-center justify-center text-slate-500 text-sm">Loading…</div>
  if (!user) return <Navigate to="/login" replace />
  if (user.must_change_password && location.pathname !== '/account/security') {
    return <Navigate to="/account/security" replace />
  }
  if (roles && !roles.includes(user.role)) return <Navigate to="/dashboard" replace />
  return <AppLayout />
}

function PublicRoute() {
  const { user, loading } = useAuth()
  if (loading) return null
  if (user) return <Navigate to="/dashboard" replace />
  return <Outlet />
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          <Route element={<PublicRoute />}>
            <Route path="/login" element={<Login />} />
            <Route path="/register" element={<Register />} />
          </Route>

          <Route element={<ProtectedRoute />}>
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/cases" element={<CasesPage />} />
            <Route path="/cases/:id" element={<CaseDetail />} />
            <Route path="/findings" element={<AllFindings />} />
            <Route path="/account/security" element={<AccountSecurity />} />
            <Route path="/traceability" element={<TraceabilityMatrix />} />
            <Route path="/roles" element={<RolesAccess />} />
          </Route>

          <Route element={<ProtectedRoute roles={['admin', 'soc_analyst', 'forensic_investigator']} />}>
            <Route path="/upload" element={<UploadPage />} />
          </Route>

          <Route element={<ProtectedRoute roles={['admin', 'compliance_officer']} />}>
            <Route path="/compliance" element={<ComplianceView />} />
            <Route path="/admin/audit-logs" element={<AuditLogs />} />
            <Route path="/admin/benchmark" element={<PerformanceBenchmark />} />
          </Route>

          <Route element={<ProtectedRoute roles={['admin']} />}>
            <Route path="/admin/users" element={<AdminUsers />} />
          </Route>

          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  )
}
