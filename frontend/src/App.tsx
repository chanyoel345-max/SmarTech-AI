
import { useEffect, useState } from "react";
import "./App.css";

type Summary = {
  total_events: number;
  failed_login_events: number;
  high_risk_events: number;
  medium_risk_events: number;
  low_risk_events: number;
};

type Alert = {
  username: string;
  ip_address: string;
  failed_attempts: number;
  risk_level: string;
};

const API = "http://127.0.0.1:8000";

function App() {
  const [summary, setSummary] = useState<Summary | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [error, setError] = useState("");


useEffect(() => {
  let active = true;

  async function loadData() {
    try {
      const [summaryResponse, alertsResponse] = await Promise.all([
        fetch(`${API}/api/summary`),
        fetch(`${API}/api/alerts`),
      ]);

      if (!summaryResponse.ok || !alertsResponse.ok) {
        throw new Error("تعذر تحميل البيانات");
      }

      const summaryData: Summary = await summaryResponse.json();
      const alertsData: Alert[] = await alertsResponse.json();

      if (active) {
        setSummary(summaryData);
        setAlerts(alertsData);
        setError("");
      }
    } catch {
      if (active) {
        setError("تعذر الاتصال بخادم التحليل. تأكدي من تشغيل FastAPI.");
      }
    }
  }

  loadData();
  const intervalId = window.setInterval(loadData, 15000);

  return () => {
    active = false;
    window.clearInterval(intervalId);
  };
}, []);


  const cards = summary
    ? [
        { title: "إجمالي الأحداث", value: summary.total_events, icon: "▤" },
        { title: "محاولات الدخول الفاشلة", value: summary.failed_login_events, icon: "⌕" },
        { title: "خطورة عالية", value: summary.high_risk_events, icon: "⚠" },
        { title: "خطورة متوسطة", value: summary.medium_risk_events, icon: "◈" },
      ]
    : [];

  return (
    <main className="dashboard" dir="rtl">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-icon">N</span>
          <div>
            <h2>NexusAI</h2>
            <small>منصة مراقبة ذكية</small>
          </div>
        </div>

        <nav>
          <a className="nav-link active" href="#overview">▦　نظرة عامة</a>
          <a className="nav-link" href="#alerts">⚠　التنبيهات الأمنية</a>
          <a className="nav-link" href="#status">◉　حالة النظام</a>
        </nav>

        <div className="sidebar-footer">
          <span className="status-dot" />
          <span>نظام التحليل المحلي</span>
        </div>
      </aside>

      <section className="main-content">
        <header className="topbar">
          <div>
            <h1>لوحة التحكم</h1>
            <p>مراقبة الأحداث وتحليل السجلات الأمنية</p>
          </div>
          <span className="live-badge">● النظام المحلي</span>
        </header>

        {error && <div className="error-banner">{error}</div>}

        <section id="overview">
          <div className="section-heading">
            <h2>ملخص الأمان</h2>
            <span>بيانات التحليل الحالية</span>
          </div>

          <div className="stats-grid">
            {cards.map((card) => (
              <article className="stat-card" key={card.title}>
                <div className="stat-top">
                  <span>{card.title}</span>
                  <span className="stat-icon">{card.icon}</span>
                </div>
                <strong>{summary ? card.value : "..."}</strong>
                <small>وفقًا للسجلات المحللة</small>
              </article>
            ))}
          </div>
        </section>

        <section id="alerts" className="alerts-section">
          <div className="section-heading">
            <h2>التنبيهات الأمنية</h2>
            <span>{alerts.length} حالات تستحق المراجعة</span>
          </div>

          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>المستخدم</th>
                  <th>عنوان IP</th>
                  <th>المحاولات الفاشلة</th>
                  <th>مستوى الخطورة</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((alert, index) => (
                  <tr key={`${alert.username}-${alert.ip_address}-${index}`}>
                    <td>{alert.username}</td>
                    <td dir="ltr">{alert.ip_address}</td>
                    <td>{alert.failed_attempts}</td>
                    <td>
                      <span className={`risk ${alert.risk_level.toLowerCase()}`}>
                        {alert.risk_level === "High"
                          ? "عالية"
                          : alert.risk_level === "Medium"
                          ? "متوسطة"
                          : "منخفضة"}
                      </span>
                    </td>
                  </tr>
                ))}
                {alerts.length === 0 && !error && summary && (
                  <tr>
                    <td colSpan={4}>لا توجد تنبيهات حاليًا</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>

        <section id="status" className="system-panel">
          <div>
            <span className="status-dot" />
            <strong>خدمة تحليل السجلات</strong>
          </div>
          <span>{summary ? "متصلة" : "بانتظار الاتصال"}</span>
        </section>

        <footer>NexusAI · نموذج أولي لتحليل الأحداث الأمنية</footer>
      </section>
    </main>
  );
}

export default App;
