
import { useCallback, useEffect, useState } from "react";
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
  recommendation?: string;
};

const API = (
  import.meta.env.VITE_API_URL || "http://127.0.0.1:8000"
).replace(/\/$/, "");

function App() {
  const [summary, setSummary] = useState<Summary | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [error, setError] = useState("");
  const [lastUpdated, setLastUpdated] = useState("");
  const [loading, setLoading] = useState(true);

  const loadData = useCallback(async () => {
    try {
      const [summaryResponse, alertsResponse] = await Promise.all([
        fetch(`${API}/api/summary`),
        fetch(`${API}/api/alerts`),
      ]);

      if (!summaryResponse.ok || !alertsResponse.ok) {
        throw new Error("تعذر تحميل البيانات من الخادم.");
      }

      const summaryData: Summary = await summaryResponse.json();
      const alertsData: Alert[] = await alertsResponse.json();

      setSummary(summaryData);
      setAlerts(alertsData);
      setError("");
      setLastUpdated(
        new Date().toLocaleTimeString("ar-SA", {
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
        })
      );
    } catch {
      setError("تعذر الاتصال بالخادم. تحققي من حالة خدمة التحليل.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadData();

    const intervalId = window.setInterval(() => {
      void loadData();
    }, 15000);

    return () => window.clearInterval(intervalId);
  }, [loadData]);

  const riskLevels = [
    {
      name: "عالية",
      count: summary?.high_risk_events ?? 0,
      className: "high",
    },
    {
      name: "متوسطة",
      count: summary?.medium_risk_events ?? 0,
      className: "medium",
    },
    {
      name: "منخفضة",
      count: summary?.low_risk_events ?? 0,
      className: "low",
    },
  ];

  const cards = [
    {
      title: "إجمالي الأحداث",
      value: summary?.total_events,
      icon: "▤",
      className: "neutral",
    },
    {
      title: "محاولات الدخول الفاشلة",
      value: summary?.failed_login_events,
      icon: "⌕",
      className: "warning",
    },
    {
      title: "أحداث عالية الخطورة",
      value: summary?.high_risk_events,
      icon: "⚠",
      className: "danger",
    },
    {
      title: "أحداث متوسطة الخطورة",
      value: summary?.medium_risk_events,
      icon: "◈",
      className: "medium",
    },
    {
      title: "أحداث منخفضة الخطورة",
      value: summary?.low_risk_events,
      icon: "✓",
      className: "safe",
    },
  ];

  return (
    <main className="dashboard" dir="rtl">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-icon">N</span>
          <div>
            <h2>NexusAI</h2>
            <small>Security Operations</small>
          </div>
        </div>

        <div className="sidebar-label">مساحة العمل</div>

        <nav>
          <a className="nav-link active" href="#overview">
            <span>▦</span> نظرة عامة
          </a>
          <a className="nav-link" href="#analytics">
            <span>◫</span> التحليل الأمني
          </a>
          <a className="nav-link" href="#alerts">
            <span>⚠</span> التنبيهات الأمنية
            {alerts.length > 0 && (
              <span className="nav-count">{alerts.length}</span>
            )}
          </a>
          <a className="nav-link" href="#recommendations">
            <span>✧</span> التوصيات الأمنية
          </a>
          <a className="nav-link" href="#status">
            <span>◉</span> حالة النظام
          </a>
        </nav>

        <div className="sidebar-footer">
          <span className={`status-dot ${error ? "offline" : ""}`} />
          <div>
            <strong>{error ? "الاتصال غير متاح" : "خدمة التحليل"}</strong>
            <small>{error ? "تحققي من الخادم" : "NexusAI API"}</small>
          </div>
        </div>
      </aside>

      <section className="main-content">
        <header className="topbar">
          <div>
            <div className="eyebrow">مركز العمليات الأمنية / SOC</div>
            <h1>نظرة عامة أمنية</h1>
            <p>مراقبة الأحداث وتحليل السجلات وتقييم مستويات المخاطر</p>
          </div>

          <div className="topbar-actions">
            <span className={`connection-badge ${error ? "disconnected" : ""}`}>
              <span className="status-dot" />
              {error ? "غير متصل" : loading ? "جارٍ الاتصال" : "الخادم متصل"}
            </span>
            <button
              className="refresh-button"
              onClick={() => void loadData()}
              disabled={loading}
            >
              ↻ تحديث البيانات
            </button>
          </div>
        </header>

        {error && (
          <div className="error-banner">
            <strong>تعذر تحديث البيانات</strong>
            <span>{error}</span>
            <button onClick={() => void loadData()}>إعادة المحاولة</button>
          </div>
        )}

        <section id="overview">
          <div className="section-heading">
            <div>
              <h2>مؤشرات الأمان الرئيسية</h2>
              <p>ملخص السجلات التي تمت معالجتها</p>
            </div>
            <span className="data-label">بيانات من الخادم</span>
          </div>

          <div className="stats-grid">
            {cards.map((card) => (
              <article
                className={`stat-card ${card.className}`}
                key={card.title}
              >
                <div className="stat-top">
                  <span>{card.title}</span>
                  <span className="stat-icon">{card.icon}</span>
                </div>
                <strong>{card.value ?? "—"}</strong>
                <small>
                  {loading && !summary
                    ? "جارٍ تحميل البيانات..."
                    : "وفقًا للسجلات المحللة"}
                </small>
              </article>
            ))}
          </div>
        </section>

        <section id="analytics" className="analytics-section">
          <div className="section-heading">
            <div>
              <h2>تحليلات المخاطر</h2>
              <p>توزيع الأحداث بحسب مستوى الخطورة</p>
            </div>
          </div>

          <div className="analytics-grid">
            <article className="panel risk-panel">
              <div className="panel-heading">
                <div>
                  <h3>توزيع مستويات الخطورة</h3>
                  <p>عدد الأحداث في كل مستوى</p>
                </div>
                <span className="panel-mark">01</span>
              </div>

              <div className="risk-chart-layout">
                <div
                  className="risk-donut"
                  style={{
                    background: `conic-gradient(
                      #fb626b 0deg ${
                        summary && summary.total_events > 0
                          ? (summary.high_risk_events /
                              summary.total_events) *
                            360
                          : 0
                      }deg,
                      #f5b94c ${
                        summary && summary.total_events > 0
                          ? (summary.high_risk_events /
                              summary.total_events) *
                            360
                          : 0
                      }deg ${
                        summary && summary.total_events > 0
                          ? ((summary.high_risk_events +
                              summary.medium_risk_events) /
                              summary.total_events) *
                            360
                          : 0
                      }deg,
                      #3dd6a0 ${
                        summary && summary.total_events > 0
                          ? ((summary.high_risk_events +
                              summary.medium_risk_events) /
                              summary.total_events) *
                            360
                          : 0
                      }deg 360deg
                    )`,
                  }}
                >
                  <div className="donut-center">
                    <strong>{summary?.total_events ?? "—"}</strong>
                    <span>حدث</span>
                  </div>
                </div>

                <div className="risk-legend">
                  {riskLevels.map((risk) => (
                    <div className="legend-row" key={risk.name}>
                      <span className={`legend-dot ${risk.className}`} />
                      <span>{risk.name}</span>
                      <strong>{risk.count}</strong>
                    </div>
                  ))}
                </div>
              </div>
            </article>

            <article className="panel distribution-panel">
              <div className="panel-heading">
                <div>
                  <h3>مقارنة مستويات المخاطر</h3>
                  <p>نسبة كل مستوى من إجمالي الأحداث</p>
                </div>
                <span className="panel-mark">02</span>
              </div>

              <div className="bar-chart">
                {riskLevels.map((risk) => {
                  const percentage =
                    summary && summary.total_events > 0
                      ? (risk.count / summary.total_events) * 100
                      : 0;

                  return (
                    <div className="bar-row" key={risk.name}>
                      <div className="bar-label">
                        <span>{risk.name}</span>
                        <strong>
                          {risk.count}{" "}
                          <small>({Math.round(percentage)}%)</small>
                        </strong>
                      </div>
                      <div className="bar-track">
                        <div
                          className={`bar-fill ${risk.className}`}
                          style={{ width: `${percentage}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>

              <div className="chart-note">
                <span className="status-dot" />
                <span>
                  التصنيف الحالي قائم على قواعد عدد محاولات الدخول.
                </span>
              </div>
            </article>
          </div>
        </section>

        <section id="alerts" className="alerts-section">
          <div className="section-heading">
            <div>
              <h2>التنبيهات الأمنية</h2>
              <p>الأحداث المصنفة عالية أو متوسطة الخطورة</p>
            </div>
            <span className="alert-counter">
              {alerts.length} تنبيهات للمراجعة
            </span>
          </div>

          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>المستخدم</th>
                  <th>عنوان IP</th>
                  <th>المحاولات الفاشلة</th>
                  <th>مستوى الخطورة</th>
                  <th>التوصية الأمنية</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((alert, index) => (
                  <tr key={`${alert.username}-${alert.ip_address}-${index}`}>
                    <td>
                      <div className="user-cell">
                        <span className="user-avatar">
                          {alert.username.slice(0, 1).toUpperCase()}
                        </span>
                        <strong>{alert.username}</strong>
                      </div>
                    </td>
                    <td>
                      <code dir="ltr">{alert.ip_address}</code>
                    </td>
                    <td>
                      <strong>{alert.failed_attempts}</strong>
                    </td>
                    <td>
                      <span
                        className={`risk ${alert.risk_level.toLowerCase()}`}
                      >
                        {alert.risk_level === "High"
                          ? "عالية"
                          : alert.risk_level === "Medium"
                            ? "متوسطة"
                            : "منخفضة"}
                      </span>
                    </td>
                    <td className="recommendation-cell">
                      {alert.recommendation || "راجع السجل يدويًا."}
                    </td>
                  </tr>
                ))}

                {alerts.length === 0 && !error && (
                  <tr>
                    <td colSpan={5} className="empty-state">
                      {loading
                        ? "جارٍ تحميل التنبيهات..."
                        : "لا توجد تنبيهات للمراجعة حاليًا."}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>

        <section id="recommendations" className="recommendations-panel">
          <div className="panel-heading">
            <div>
              <h3>أولويات المراجعة الأمنية</h3>
              <p>مقترحات مبنية على نتائج التحليل الحالي</p>
            </div>
            <span className="panel-mark">03</span>
          </div>

          {alerts.length === 0 ? (
            <p className="recommendation-summary">
              لا توجد تنبيهات تحتاج إلى مراجعة وفق النتائج الحالية.
            </p>
          ) : (
            <div className="priority-list">
              {alerts
                .slice()
                .sort(
                  (a, b) =>
                    b.failed_attempts - a.failed_attempts
                )
                .slice(0, 3)
                .map((alert, index) => (
                  <article
                    className="priority-item"
                    key={`${alert.ip_address}-${alert.username}`}
                  >
                    <span className="priority-number">
                      {String(index + 1).padStart(2, "0")}
                    </span>
                    <div className="priority-content">
                      <strong>
                        {alert.username} · {alert.ip_address}
                      </strong>
                      <p>
                        {alert.recommendation ||
                          "راجع السجل وتحقق من النشاط المرتبط به."}
                      </p>
                    </div>
                    <span
                      className={`risk ${alert.risk_level.toLowerCase()}`}
                    >
                      {alert.risk_level === "High" ? "عالية" : "متوسطة"}
                    </span>
                  </article>
                ))}
            </div>
          )}
        </section>

        <section id="status" className="system-panel">
          <div className="system-status-title">
            <span className={`status-dot ${error ? "offline" : ""}`} />
            <div>
              <strong>خدمة تحليل السجلات</strong>
              <small>FastAPI · Render</small>
            </div>
          </div>
          <div className="system-status-details">
            <span>{error ? "غير متصلة" : "حالة الاتصال سليمة"}</span>
            <small>
              آخر تحديث: {lastUpdated || "لم يتم التحديث بعد"}
            </small>
          </div>
        </section>

        <footer>
          <strong>NexusAI</strong>
          <span>منصة تحليل السجلات الأمنية</span>
          <span>نموذج أولي · البيانات المعروضة تعتمد على السجلات المتاحة</span>
        </footer>
      </section>
    </main>
  );
}

export default App;
