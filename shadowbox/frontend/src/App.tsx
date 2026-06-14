import { Outlet, Link } from 'react-router-dom';

export default function App() {
  return (
    <>
      <nav className="navbar">
        <div className="navbar-inner">
          <Link to="/" className="navbar-brand">
            <div className="navbar-logo">🔬</div>
            <div>
              <div className="navbar-title">ShadowBox</div>
              <div className="navbar-subtitle">Consequence Visualization Engine</div>
            </div>
          </Link>
          <div className="navbar-status">
            <div className="status-indicator" />
            <span>Engine Active</span>
          </div>
        </div>
      </nav>
      <main className="app-container" style={{ padding: '32px 24px' }}>
        <Outlet />
      </main>
    </>
  );
}
