
import { useCallback, useEffect, useState } from "react";
import { onAuthStateChanged, signOut } from "firebase/auth";

import { auth } from "./firebase";
import Login from "./Longin";
import Register from "./Register";

import Overview from "./pages/Overview";
import Alerts from "./pages/Alerts";
import SecurityAnalysis from "./pages/SecurityAnalysis";
import Recommendations from "./pages/Recommendations";
import LogAnalysis from "./pages/LogAnalysis";
import SystemStatus from "./pages/SystemStatus";

import type { Summary, SecurityAlert, PageId } from "./types";
import "./App.css";

const API_BASE = (
  import.meta.env.VITE_API_URL || "https://smartech-ai.onrender.com"
).replace(/\/+$/, "");

const navigation: { id: PageId; label: string }[] = [
  { id: "overview", label: "نظرة عامة" },
  { id: "analysis", label: "تحليل الأمن" },
  { id: "alerts", label: "التنبيهات" },
  { id: "recommendations", label: "التوصيات" },
  { id: "logs", label: "تحليل السجلات" },
  { id: "status", label: "حالة النظام" },
];

export default function App() {
  const [userChecked, setUserChecked] = useState(false);
  const [loggedIn, setLoggedIn] = useState(false);
  const [authPage, setAuthPage] = useState<"login" | "register">("login");

  const [page, setPage] = useState<PageId>("overview");
  const [summary, setSummary] = useState<Summary | null>(null);
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

useEffect(() => {
    const unsubscribe = onAuthStateChanged(
      auth,
      (user) => {
        setLoggedIn(Boolean(user));
        setUserChecked(true);
      },
      (authError) => {
        console.error("Firebase authentication error:", authError);
        setLoggedIn(false);
        setUserChecked(true);
      }
    );

    return unsubscribe;
  }, []);

  const loadData = useCallback(async () => {
    const user = auth.currentUser;

    if (!user) {
      setSummary(null);
      setAlerts([]);
      setError("انتهت جلسة تسجيل الدخول. سجّلي الدخول مرة أخرى.");
      return;
    }

    setLoading(true);
    setError("");

    try {
      const token = await user.getIdToken();

      const headers = {
        Authorization: `Bearer ${token}`,
      };

      const [summaryResponse, alertsResponse] = await Promise.all([
        fetch(`${API_BASE}/api/summary`, { headers }),
        fetch(`${API_BASE}/api/alerts`, { headers }),
      ]);

      if (
        summaryResponse.status === 401 ||
        alertsResponse.status === 401
      ) {
        throw new Error(
          "رفض الخادم رمز المصادقة. سجّلي الخروج ثم الدخول مرة أخرى، وإذا استمرت المشكلة نراجع إعداد Firebase Admin."
        );
      }

      if (!summaryResponse.ok || !alertsResponse.ok) {
        throw new Error(
          `تعذر تحميل البيانات. حالة الملخص: ${summaryResponse.status}، حالة التنبيهات: ${alertsResponse.status}.`
        );
      }

      const summaryData: Summary = await summaryResponse.json();
      const alertsData: SecurityAlert[] = await alertsResponse.json();

      setSummary(summaryData);
      setAlerts(alertsData);
    } catch (err) {
      console.error("Data loading error:", err);

      setError(
        err instanceof Error
          ? err.message
          : "تعذر تحميل البيانات من الخادم."
      );
    } finally {
      setLoading(false);
    }
  }, []);
  useEffect(() => {
    if (!loggedIn) {
      setSummary(null);
      setAlerts([]);
      return;
    }

    void loadData();

    const timer = window.setInterval(() => {
      void loadData();
    }, 30000);

    return () => window.clearInterval(timer);
  }, [loggedIn, loadData]);

async function handleLogout() {
    try {
      await signOut(auth);
      setPage("overview");
      setAuthPage("login");
      setSummary(null);
      setAlerts([]);
      setError("");
    } catch (err) {
      console.error("Logout error:", err);
      setError("تعذر تسجيل الخروج. حاولي مرة أخرى.");
    }
  }

function renderPage() {
    switch (page) {
      case "analysis":
        return <SecurityAnalysis alerts={alerts} loading={loading} />;

      case "alerts":
        return <Alerts alerts={alerts} loading={loading} />;

      case "recommendations":
        return <Recommendations alerts={alerts} loading={loading} />;

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

if (!userChecked) {
    return (
      <main
        dir="rtl"
        style={{
          minHeight: "100vh",
          display: "grid",
          placeItems: "center",
          background: "#080d18",
          color: "#55e6a5",
          fontFamily: "Tahoma, Arial, sans-serif",
        }}
      >
        جارٍ التحقق من تسجيل الدخول...
      </main>
    );
  }
if (!loggedIn) {
    if (authPage === "register") {
      return (
        <Register
          onRegister={() => setLoggedIn(true)}
          onGoToLogin={() => setAuthPage("login")}
        />
      );
    }

    return (
      <Login
        onLogin={() => setLoggedIn(true)}
        onGoToRegister={() => setAuthPage("register")}
      />
    );
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
          onClick={() => void handleLogout()}
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
