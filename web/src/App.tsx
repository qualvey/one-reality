import { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { SmartFinder } from './components/SmartFinder';
import { TargetTable } from './components/TargetTable';
import { ASNTable } from './components/ASNTable';
import { StatsDashboard } from './components/StatsDashboard';

export function App() {
  const [currentTab, setCurrentTab] = useState<'smart' | 'assets' | 'asns' | 'stats'>('smart');
  const [serviceOnline, setServiceOnline] = useState(false);

  const checkHealth = async () => {
    try {
      const res = await fetch('/api/health');
      if (res.ok) {
        setServiceOnline(true);
      } else {
        setServiceOnline(false);
      }
    } catch (_) {
      setServiceOnline(false);
    }
  };

  useEffect(() => {
    checkHealth();
    const interval = setInterval(checkHealth, 8000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="app-container">
      <Navbar
        currentTab={currentTab}
        onTabChange={setCurrentTab}
        serviceOnline={serviceOnline}
        onRefreshStats={checkHealth}
      />

      <main className="content-wrapper">
        {currentTab === 'smart' && <SmartFinder />}
        {currentTab === 'assets' && <TargetTable />}
        {currentTab === 'asns' && <ASNTable />}
        {currentTab === 'stats' && <StatsDashboard />}
      </main>

      <footer style={{ borderTop: '1px solid var(--border-subtle)', padding: '24px 32px', textAlign: 'center', fontSize: '0.8rem', color: 'var(--text-sub)' }}>
        reasni · 面向 REALITY 协议的高保真伪装发现与智能权重资产库
      </footer>
    </div>
  );
}

export default App;
