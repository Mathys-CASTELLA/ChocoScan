import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { Layout } from './components/Layout'
import { Dashboard } from './pages/Dashboard'
import { NewScan } from './pages/NewScan'
import { ScanDetail } from './pages/ScanDetail'
import { History } from './pages/History'

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<Dashboard />} />
          <Route path="scan" element={<NewScan />} />
          <Route path="scan/:id" element={<ScanDetail />} />
          <Route path="history" element={<History />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
