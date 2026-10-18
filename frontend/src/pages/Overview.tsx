
import type { Summary, SecurityAlert } from "../types";

type Props = {
  summary: Summary | null;
  alerts: SecurityAlert[];
  loading: boolean;
};

export default function Overview({
  summary,
  alerts,
  loading,
}: Props) {
  const total = summary?.total_events ?? 0;

  const stats = [
    {
      title: "إجمالي الأحداث",
      value: total,
      icon: "▤",
      color: "",
    },
    {
      title: "محاولات الدخول الفاشلة",
      value: summary?.failed_login_events ?? 0,
      icon: "⌕",
      color: "warning",
    },
    {
      title: "أحداث عالية الخطورة",
      value: summary?.high_risk_events ?? 0,
      icon: "⚠",
      color: "danger",
    },
    {
      title: "أحداث متوسطة الخطورة",
      value: summary?.medium_risk_events ?? 0,
      icon: "◈",
      color: "medium",
    },
    {
      title: "أحداث منخفضة الخطورة",
      value: summary?.low_risk_events ?? 0,
      icon: "✓",
      color: "safe",
    },
  ];

  const risks = [
    {
      label: "عالية",
      count: summary?.high_risk_events ?? 0,
      color: "#fb626b",
      className: "high",
    },
    {
      label: "متوسطة",
      count: summary?.medium_risk_events ?? 0,
      color: "#f5b94c",
      className: "medium",
    },
    {
      label: "منخفضة",
      count: summary?.low_risk_events ?? 0,
      color: "#3dd6a0",
      className: "low",
    },
  ];

  const highPercent =
    total > 0 ? (risks[0].count / total) * 100 : 0;

  const mediumPercent =
    total > 0
      ? ((risks[0].count + risks[1].count) / total) * 100
      : 0;

  const donutStyle = {
    background:
      total > 0
        ? `conic-gradient(
            #fb626b 0% ${highPercent}%,
            #f5b94c ${highPercent}% ${mediumPercent}%,
            #3dd6a0 ${mediumPercent}% 100%
          )`
        : "#263448",
  };

  function getArabicRisk(risk: string) {
    switch (risk.toLowerCase()) {
      case "high":
        return "عالية";
      case "medium":
        return "متوسطة";
      case "low":
        return "منخفضة";
      default:
        return "غير محددة";
    }
  }

  return (
    <div className="page-container" dir="rtl">
      <header className="topbar">
        <div>
          <p className="eyebrow">SOC / مركز العمليات الأمنية</p>
          <h1>نظرة عامة أمنية</h1>
          <p>
            مراقبة الأحداث وتحليل السجلات وتقييم مستويات المخاطر.
          </p>
        </div>

        <div className="topbar-actions">
          <span className="connection-badge">
            <span
              className={`status-dot ${loading ? "" : "online"}`}
            />
            {loading ? "جارٍ تحميل البيانات" : "عرض البيانات"}
          </span>
        </div>
      </header>

      <section>
        <div className="section-heading">
          <div>
            <h2>مؤشرات الأمان الرئيسية</h2>
            <p>ملخص الأحداث التي تمت معالجتها</p>
          </div>
          <span className="data-label">بيانات من الخادم</span>
        </div>

        <div className="stats-grid">
          {stats.map((stat) => (
            <article
              className={`stat-card ${stat.color}`}
              key={stat.title}
            >
              <div className="stat-top">
                <span>{stat.title}</span>
                <span className="stat-icon">{stat.icon}</span>
              </div>

              <strong>{loading ? "—" : stat.value}</strong>
              <small>وفقًا للسجلات المحللة</small>
            </article>
          ))}
        </div>
      </section>

      <section className="analytics-section">
        <div className="section-heading">
          <div>
            <h2>تحليلات المخاطر</h2>
            <p>توزيع الأحداث بحسب مستوى الخطورة</p>
          </div>
        </div>

        <div className="analytics-grid">
          <article className="panel">
            <div className="panel-heading">
              <div>
                <h3>توزيع مستويات الخطورة</h3>
                <p>عدد الأحداث في كل مستوى</p>
              </div>
              <span className="panel-mark">01</span>
            </div>

            <div className="risk-chart-layout">
              <div className="risk-donut" style={donutStyle}>
                <div className="donut-center">
                  <strong>{loading ? "—" : total}</strong>
                  <span>حدث</span>
                </div>
              </div>

              <div className="risk-legend">
                {risks.map((risk) => (
                  <div className="legend-row" key={risk.label}>
                    <span
                      className={`legend-dot ${risk.className}`}
                    />
                    <span>{risk.label}</span>
                    <strong>
                      {loading ? "—" : risk.count}
                    </strong>
                  </div>
                ))}
              </div>
            </div>

            <p className="chart-note">
              التوزيع مبني على أعداد الأحداث التي أعادها الخادم.
            </p>
          </article>

          <article className="panel">
            <div className="panel-heading">
              <div>
                <h3>مقارنة مستويات المخاطر</h3>
                <p>نسبة كل مستوى من إجمالي الأحداث</p>
              </div>
              <span className="panel-mark">02</span>
            </div>

            <div className="bar-chart">
              {risks.map((risk) => {
                const percent =
                  total > 0 ? (risk.count / total) * 100 : 0;

                return (
                  <div key={risk.label}>
                    <div className="bar-label">
                      <span>{risk.label}</span>
                      <strong>
                        {loading
                          ? "—"
                          : `${risk.count} (${Math.round(percent)}%)`}
                      </strong>
                    </div>

                    <div className="bar-track">
                      <div
                        className={`bar-fill ${risk.className}`}
                        style={{
                          width: `${loading ? 0 : percent}%`,
                        }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </article>
        </div>
      </section>

      <section className="alerts-section">
        <div className="section-heading">
          <div>
            <h2>ملخص التنبيهات</h2>
            <p>أحدث التنبيهات ضمن البيانات المحملة</p>
          </div>
          <span className="alert-counter">
            {loading ? "—" : alerts.length}
          </span>
        </div>

        <div className="panel">
          {loading ? (
            <div className="empty-state">
              جارٍ تحميل التنبيهات...
            </div>
          ) : alerts.length === 0 ? (
            <div className="empty-state">
              لا توجد تنبيهات متاحة حاليًا.
            </div>
          ) : (
            <div className="table-container">
              <table>
                <thead>
                  <tr>
                    <th>المستخدم</th>
                    <th>عنوان IP</th>
                    <th>المحاولات الفاشلة</th>
                    <th>مستوى الخطورة</th>
                    <th>الحدث</th>
                  </tr>
                </thead>

                <tbody>
                  {alerts.slice(0, 5).map((alert, index) => (
                    <tr
                      key={`${alert.username}-${alert.ip_address}-${index}`}
                    >
                      <td>{alert.username || "غير معروف"}</td>
                      <td>
                        <code>{alert.ip_address || "—"}</code>
                      </td>
                      <td>{alert.failed_attempts}</td>
                      <td>
                        <span
                          className={`risk ${
                            ["high", "medium", "low"].includes(
                              alert.risk_level.toLowerCase(),
                            )
                              ? alert.risk_level.toLowerCase()
                              : ""
                          }`}
                        >
                          {getArabicRisk(alert.risk_level)}
                        </span>
                      </td>
                      <td>{alert.event || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </section>

      <section className="panel">
        <div className="panel-heading">
          <div>
            <h3>ملخص الحالة الأمنية</h3>
            <p>مؤشرات مأخوذة من السجلات المتاحة</p>
          </div>
        </div>

        <div className="dashboard-grid">
          <div className="dashboard-card">
            <h2>إجمالي السجلات</h2>
            <strong>{loading ? "—" : total}</strong>
          </div>

          <div className="dashboard-card">
            <h2>عالية الخطورة</h2>
            <strong>
              {loading ? "—" : summary?.high_risk_events ?? 0}
            </strong>
          </div>

          <div className="dashboard-card">
            <h2>التنبيهات المسجلة</h2>
            <strong>{loading ? "—" : alerts.length}</strong>
          </div>
        </div>

        <p className="chart-note">
          هذه النتائج مبنية على السجلات المتاحة في الخادم، ولا تعني
          أن الشبكة الفعلية تتم مراقبتها مباشرة.
        </p>
      </section>
    </div>
  );
}
