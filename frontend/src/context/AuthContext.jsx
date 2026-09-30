import { createContext, useContext, useState, useEffect } from 'react'
import { AuthAPI } from '../api/client'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const token = localStorage.getItem('sms_token')
    const cachedUser = localStorage.getItem('sms_user')
    if (token && cachedUser) {
      setUser(JSON.parse(cachedUser))
    }
    setLoading(false)
  }, [])

  const _persist = (res) => {
    localStorage.setItem('sms_token', res.data.access_token)
    if (res.data.refresh_token) localStorage.setItem('sms_refresh', res.data.refresh_token)
    localStorage.setItem('sms_user', JSON.stringify(res.data.user))
    setUser(res.data.user)
    return res.data.user
  }

  const login = async (email, password) => {
    const res = await AuthAPI.login(email, password)
    return _persist(res)
  }

  const register = async (data) => {
    const res = await AuthAPI.register(data)
    return _persist(res)
  }

  const refreshMe = async () => {
    const res = await AuthAPI.me()
    localStorage.setItem('sms_user', JSON.stringify(res.data))
    setUser(res.data)
    return res.data
  }

  const logout = () => {
    localStorage.removeItem('sms_token')
    localStorage.removeItem('sms_refresh')
    localStorage.removeItem('sms_user')
    setUser(null)
  }

  return (
    <AuthContext.Provider value={{ user, loading, login, register, logout, refreshMe }}>
      {children}
    </AuthContext.Provider>
  )
}

export const useAuth = () => useContext(AuthContext)

export const ROLE_LABELS = {
  admin: 'System Administrator',
  soc_analyst: 'SOC Analyst',
  forensic_investigator: 'Forensic Investigator',
  compliance_officer: 'Compliance Officer',
}

export const ROLE_COLORS = {
  admin: 'bg-purple-500/15 text-purple-300 border-purple-500/30',
  soc_analyst: 'bg-blue-500/15 text-blue-300 border-blue-500/30',
  forensic_investigator: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
  compliance_officer: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
}

// Role-based UI improvement: each role's stated responsibility, authority
// (what they alone can do), and working scope, surfaced on the Roles &
// Access page and usable anywhere a role needs explaining rather than
// just gating.
export const ROLE_DETAILS = {
  admin: {
    responsibility: 'Owns the platform: account lifecycle, security policy, and system-wide oversight.',
    authority: [
      'Create, promote, deactivate, and delete user accounts',
      'Set the organization-wide cipher/TLS security policy',
      'View and verify the tamper-evident audit trail',
      'View every case regardless of who uploaded it',
    ],
    workingScope: 'Full access to every case, every finding, and every admin control. Uploads and analyzes captures like an analyst, plus manages the platform.',
    cannotDo: [],
  },
  soc_analyst: {
    responsibility: 'Front-line triage: upload captures, work findings, track remediation.',
    authority: [
      'Upload PCAP captures for analysis',
      'Update remediation status on findings (open → assigned → fixed → verified)',
      'Add investigator notes to a case',
    ],
    workingScope: 'Own cases only, unless promoted to admin/compliance visibility. Cannot see other analysts\u2019 cases, manage users, or change the security policy.',
    cannotDo: ['Manage user accounts', 'View/edit the org-wide security policy', 'View the audit trail'],
  },
  forensic_investigator: {
    responsibility: 'Deep-dive evidence analysis: packet-level reconstruction, chain of custody, certificate/IOC correlation.',
    authority: [
      'Upload PCAP captures for analysis',
      'Update remediation status on findings',
      'Inspect packet-level evidence and chain of custody for a case',
    ],
    workingScope: 'Own cases, with the same investigative surface as a SOC analyst plus the forensic evidence views (packet viewer, custody log, certificate reuse).',
    cannotDo: ['Manage user accounts', 'View/edit the org-wide security policy', 'View the audit trail'],
  },
  compliance_officer: {
    responsibility: 'Independent oversight: read-only visibility across all cases, policy, and the audit trail for compliance reporting.',
    authority: [
      'View every case, finding, and report across the organization',
      'View and edit the org-wide cipher/TLS security policy',
      'View and verify the tamper-evident audit trail',
      'Export compliance-mapped reports',
    ],
    workingScope: 'Read-only over case data (cannot upload, cannot change remediation status) but has policy-setting and audit authority admins share.',
    cannotDo: ['Upload captures', 'Update finding remediation status', 'Manage user accounts'],
  },
}
