import axios from 'axios'

// Same-origin '/api' is correct for the docker-compose deployment (nginx
// reverse-proxies /api/ to the backend container) and for local dev (Vite's
// dev-server proxy). It is WRONG whenever frontend and backend are deployed
// as separate services with separate origins -- which is exactly Render's
// normal setup (a Static Site + a separate Web Service, on two different
// *.onrender.com domains). VITE_API_BASE_URL lets the build point at the
// deployed backend's absolute URL in that case; see docs/DEPLOYMENT_RENDER.md.
const api = axios.create({ baseURL: import.meta.env.VITE_API_BASE_URL || '/api' })

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('sms_token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

let refreshing = null

api.interceptors.response.use(
  (res) => res,
  async (err) => {
    const original = err.config
    if (err.response?.status === 401 && !original._retried && localStorage.getItem('sms_refresh')) {
      original._retried = true
      try {
        refreshing = refreshing || api.post('/auth/refresh', { refresh_token: localStorage.getItem('sms_refresh') })
        const res = await refreshing
        refreshing = null
        localStorage.setItem('sms_token', res.data.access_token)
        localStorage.setItem('sms_refresh', res.data.refresh_token)
        localStorage.setItem('sms_user', JSON.stringify(res.data.user))
        original.headers.Authorization = `Bearer ${res.data.access_token}`
        return api(original)
      } catch (refreshErr) {
        refreshing = null
        localStorage.removeItem('sms_token')
        localStorage.removeItem('sms_refresh')
        localStorage.removeItem('sms_user')
        window.location.href = '/login'
        return Promise.reject(refreshErr)
      }
    }
    if (err.response?.status === 401) {
      localStorage.removeItem('sms_token')
      localStorage.removeItem('sms_refresh')
      localStorage.removeItem('sms_user')
      window.location.href = '/login'
    }
    return Promise.reject(err)
  }
)

export const AuthAPI = {
  login: (email, password) => api.post('/auth/login', { email, password }),
  register: (data) => api.post('/auth/register', data),
  me: () => api.get('/auth/me'),
  changePassword: (current_password, new_password) => api.post('/auth/change-password', { current_password, new_password }),
}

export const CaseAPI = {
  upload: (file, caseName, onProgress) => {
    const form = new FormData()
    form.append('file', file)
    form.append('case_name', caseName)
    return api.post('/cases/upload', form, {
      headers: { 'Content-Type': 'multipart/form-data' },
      onUploadProgress: onProgress,
    })
  },
  list: () => api.get('/cases'),
  get: (id) => api.get(`/cases/${id}`),
  sessions: (id) => api.get(`/cases/${id}/sessions`),
  findings: (id) => api.get(`/cases/${id}/findings`),
  delete: (id) => api.delete(`/cases/${id}`),
  timeline: (id) => api.get(`/cases/${id}/timeline`),
  iocs: (id) => api.get(`/cases/${id}/iocs`),
  certReuse: (id) => api.get(`/cases/${id}/certificates/reuse`),
  comments: (id) => api.get(`/cases/${id}/comments`),
  addComment: (id, body) => {
    const form = new FormData()
    form.append('body', body)
    return api.post(`/cases/${id}/comments`, form, { headers: { 'Content-Type': 'multipart/form-data' } })
  },
  updateRemediation: (findingId, status, assignedTo) => {
    const params = new URLSearchParams({ status })
    if (assignedTo) params.append('assigned_to', assignedTo)
    return api.patch(`/cases/findings/${findingId}/remediation?${params.toString()}`)
  },
  custody: (id) => api.get(`/cases/${id}/custody`),
  packets: (caseId, sessionId) => api.get(`/cases/${caseId}/sessions/${sessionId}/packets`),
  benchmark: () => api.get('/cases/benchmark'),
}

export const ReportAPI = {
  json: (id) => api.get(`/reports/${id}/json`),
  // NOT plain <a href> targets: these hit an authenticated endpoint, and a
  // normal browser navigation/anchor click does not attach the
  // Authorization header our axios interceptor adds -- that would 401 in
  // any deployment stricter than "everything on one trusted origin with
  // no real auth enforcement". Fetch through axios (auth header attached)
  // and hand the caller an object URL to open/download instead.
  fetchHtml: (id) => api.get(`/reports/${id}/html`, { responseType: 'blob' }),
  fetchPdf: (id) => api.get(`/reports/${id}/pdf`, { responseType: 'blob' }),
}

export const DashboardAPI = {
  summary: () => api.get('/dashboard/summary'),
  riskTrend: () => api.get('/dashboard/risk-trend'),
  baseline: () => api.get('/dashboard/baseline'),
  traceabilityMatrix: () => api.get('/dashboard/traceability-matrix'),
}

export const AdminAPI = {
  listUsers: () => api.get('/admin/users'),
  createUser: (data) => api.post('/admin/users', data),
  updateRole: (userId, role) => api.patch(`/admin/users/${userId}/role?role=${role}`),
  toggleStatus: (userId, isActive) => api.patch(`/admin/users/${userId}/status?is_active=${isActive}`),
  auditLogs: (limit = 200) => api.get(`/admin/audit-logs?limit=${limit}`),
  verifyAuditChain: () => api.get('/admin/audit-logs/verify'),
  getPolicy: () => api.get('/admin/policy'),
  updatePolicy: (data) => api.put('/admin/policy', data),
}

export default api
