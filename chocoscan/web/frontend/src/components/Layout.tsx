import { NavLink, Outlet } from 'react-router-dom'

const NAV = [
  { to: '/',        label: 'Dashboard'    },
  { to: '/scan',    label: 'Nouveau scan' },
  { to: '/history', label: 'Historique'   },
]

export function Layout() {
  return (
    <div className="flex h-screen overflow-hidden">
      {/* Sidebar */}
      <aside className="w-56 flex-shrink-0 bg-choco-surface border-r border-choco-border flex flex-col">
        {/* Logo */}
        <div className="px-2 py-3 border-b border-choco-border flex justify-center">
          <img src="/logo.png" alt="ChocoScan" className="w-full object-contain" />
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-2 py-3 space-y-0.5">
          {NAV.map(({ to, label }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) =>
                `flex items-center px-3 py-2 rounded-lg text-sm transition-colors duration-150
                 ${isActive
                   ? 'bg-choco-accent/10 text-choco-accent font-medium'
                   : 'text-choco-text-dim hover:text-choco-text hover:bg-choco-surface2'}`
              }
            >
              {label}
            </NavLink>
          ))}
        </nav>

        {/* Footer sidebar */}
        <div className="px-5 py-4 border-t border-choco-border">
          <p className="text-[11px] text-choco-muted leading-relaxed">
            Basé sur NVD · CISA KEV<br />
            <span className="text-choco-text-dim">by Kinder-Bueno</span>
          </p>
        </div>
      </aside>

      {/* Contenu principal */}
      <main className="flex-1 overflow-y-auto bg-choco-bg">
        <Outlet />
      </main>
    </div>
  )
}
