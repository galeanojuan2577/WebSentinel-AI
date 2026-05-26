import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { DashboardLayout } from './layouts/DashboardLayout'
import { DashboardHome } from './pages/Dashboard'
import { WebScan } from './pages/WebScan'
import { LinkScan } from './pages/LinkScan'
import { NetworkScan } from './pages/NetworkScan'
import { NoirAudit } from './pages/NoirAudit'
import { Pipeline } from './pages/Pipeline'
import { Findings } from './pages/Findings'
import { Landing } from './pages/Landing'
import { Login } from './pages/Login'

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route path="/login" element={<Login />} />
        <Route path="/landing" element={<Landing />} />
        <Route element={<DashboardLayout />}>
          <Route path="/dashboard" element={<DashboardHome />} />
          <Route path="/web" element={<WebScan />} />
          <Route path="/link" element={<LinkScan />} />
          <Route path="/network" element={<NetworkScan />} />
          <Route path="/noir" element={<NoirAudit />} />
          <Route path="/pipeline" element={<Pipeline />} />
          <Route path="/findings" element={<Findings />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
