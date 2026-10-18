
import { useEffect, useState } from "react";
import Overview from "./pages/Overview";
import Alerts from "./pages/Alerts";
import SecurityAnalysis from "./pages/SecurityAnalysis";
import Recommendations from "./pages/Recommendations";
import LogAnalysis from "./pages/LogAnalysis";
import SystemStatus from "./pages/SystemStatus";
import Login from "./pages/Login";
import type { Summary, SecurityAlert, PageId } from "./types";
import "./App.css";

const API_BASE = (
  import.meta.env.VITE_API_URL || "http://127.0.0.1:8000"
).replace(/\/$/, "");

const navigation: { id: PageId; label: string }[] = [
  { id: "overview", label: "نظرة عامة" },
  { id: "analysis", label: "تحليل الأمن" },
  { id: "alerts", label: "التنبيهات" },
  { id: "recommendations", label: "التوصيات" },
  { id: "logs", label: "تحليل السجلات" },
  { id: "status", label: "حالة النظام" },
];

export default function App() {
  const [loggedIn, setLoggedIn] = useState(false);
  const [page, setPage] = useState<PageId>("overview");
  const [summary, setSummary] = useState<Summary | null>(null);
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  async function loadData() {
    try {
      setError("");

      const [summaryResponse, alertsResponse] = await Promise.all([
        fetch(`${API_BASE}/api/summary`),
        fetch(`${API_BASE}/api/alerts`),
      ]);

      if (!summaryResponse.ok || !alertsResponse.ok) {
        throw new Error("تعذر تحميل بيانات الخادم.");
      }

      const summaryData: Summary = await summaryResponse.json();
      const alertsData: SecurityAlert[] = await alertsResponse.json();

      setSummary(summaryData);
    setAlerts(alertsData);
    } catch {
      setError(
        "تعذر الاتصال بالخادم. تحققي من تشغيل الباك إند ورابط API."
      );
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (!loggedIn) return;

    void loadData();

    const timer = window.setInterval(() => {
      void loadData();
    }, 30000);

    return () => window.clearInterval(timer);
  }, [loggedIn]);

  function handleLogout() {
    setLoggedIn(false);
    setPage("overview");
    setError("");
  }

  function renderPage() {
    switch (page) {
      case "analysis":
        return <SecurityAnalysis alerts={alerts} loading={loading} />;

      case "alerts":
        return <Alerts alerts={alerts} loading={loading} />;

      case "recommendations":
        return (
          <Recommendations alerts={alerts} loading={loading} />
        );

      case "logs":
        return <LogAnalysis alerts={alerts} loading={loading} />;

      case "status":
        return <SystemStatus apiBase={API_BASE} />;

      default:
        return (
          <Overview
            summary={summary}
            alerts={alerts}
            loading={loading}
          />
        );
    }
  }

  if (!loggedIn) {
    return <Login onLogin={() => setLoggedIn(true)} />;
  }

  return (
    <div className="app-shell" dir="rtl">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">N</div>
          <div>
            <strong>NexusAI</strong>
            <span>منصة البنية التحتية الذكية</span>
          </div>
        </div>

        <p className="nav-caption">القائمة الرئيسية</p>

        <nav className="navigation">
          {navigation.map((item) => (
            <button
              type="button"
              key={item.id}
              className={`nav-link ${page === item.id ? "active" : ""}`}
              onClick={() => setPage(item.id)}
            >
              {item.label}
            </button>
          ))}
        </nav>

        <button
          type="button"
          className="secondary-button"
          onClick={() => void loadData()}
          disabled={loading}
        >
          {loading ? "جارٍ التحديث..." : "تحديث البيانات"}
        </button>

        <button
          type="button"
          className="secondary-button"
          onClick={handleLogout}
        >
          تسجيل الخروج
        </button>
      </aside>

      <main className="main-area">
        {error && (
          <div className="error-banner" role="alert">
            {error}
          </div>
        )}

        {renderPage()}

        <footer className="app-footer">
          <strong>NexusAI</strong>
          <span>لوحة إدارة وتحليل البنية التحتية</span>
        </footer>
      </main>
    </div>
  );
}
