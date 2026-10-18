
import { useMemo, useState } from "react";
import type { SecurityAlert } from "../types";

type Props = {
  alerts: SecurityAlert[];
  loading: boolean;
};

export default function Alerts({ alerts, loading }: Props) {
  const [search, setSearch] = useState("");
  const [riskFilter, setRiskFilter] = useState("all");

  const filteredAlerts = useMemo(() => {
    const query = search.trim().toLowerCase();

    return alerts.filter((alert) => {
      const username = (alert.username ?? "").toLowerCase();
      const ip = (alert.ip_address ?? "").toLowerCase();
      const risk = (alert.risk_level ?? "").toLowerCase();
      const event = (alert.event ?? "").toLowerCase();

      return (
        (username.includes(query) ||
          ip.includes(query) ||
          risk.includes(query) ||
          event.includes(query)) &&
        (riskFilter === "all" || risk === riskFilter)
      );
    });
  }, [alerts, search, riskFilter]);

  function arabicRisk(risk: string) {
    if (risk === "high") return "عالية";
    if (risk === "medium") return "متوسطة";
    if (risk === "low") return "منخفضة";
    return "غير محددة";
  }

  return (
    <main className="page-container" dir="rtl">
      <header className="topbar">
        <div>
          <p className="eyebrow">SOC / SECURITY ALERTS</p>
          <h1>التنبيهات الأمنية</h1>
          <p>البحث في التنبيهات المسجلة وتصنيفها حسب الخطورة.</p>
        </div>
        <span className="alert-counter">
          {loading ? "جارٍ التحميل" : `${filteredAlerts.length} تنبيه`}
        </span>
      </header>

      <section className="panel">
        <div className="section-heading">
          <div>
            <h2>البحث والتصفية</h2>
            <p>ابحثي باسم المستخدم أو عنوان IP أو الحدث.</p>
          </div>
        </div>

        <div className="content-grid">
          <div>
            <label htmlFor="alert-search">البحث</label>
            <input
              id="alert-search"
              type="search"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="اسم المستخدم أو عنوان IP..."
            />
          </div>
          <div>
            <label htmlFor="alert-risk-filter">مستوى الخطورة</label>
            <select
              id="alert-risk-filter"
              value={riskFilter}
              onChange={(event) => setRiskFilter(event.target.value)}
            >
              <option value="all">جميع المستويات</option>
              <option value="high">عالية</option>
              <option value="medium">متوسطة</option>
              <option value="low">منخفضة</option>
            </select>
          </div>
        </div>
      </section>

      <section className="panel">
        <div className="panel-heading">
          <div>
            <h3>سجل التنبيهات</h3>
            <p>تفاصيل الأحداث التي أعادها الخادم.</p>
          </div>
          <span className="panel-mark">
            {loading ? "—" : filteredAlerts.length}
          </span>
        </div>

        {loading ? (
          <div className="empty-state">جارٍ تحميل التنبيهات...</div>
        ) : filteredAlerts.length === 0 ? (
          <div className="empty-state">لا توجد نتائج مطابقة.</div>
        ) : (
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>المستخدم</th>
                  <th>عنوان IP</th>
                  <th>المحاولات الفاشلة</th>
                  <th>الخطورة</th>
                  <th>الحدث</th>
                  <th>التوصية</th>
                </tr>
              </thead>
              <tbody>
                {filteredAlerts.map((alert, index) => {
                  const risk = (alert.risk_level ?? "").toLowerCase();
                  const riskClass = ["high", "medium", "low"].includes(risk)
                    ? risk
                    : "";

                  return (
                    <tr key={`${alert.username}-${alert.ip_address}-${index}`}>
                      <td>{alert.username || "غير معروف"}</td>
                      <td><code>{alert.ip_address || "—"}</code></td>
                      <td>{Number(alert.failed_attempts) || 0}</td>
                      <td>
                        <span className={`risk ${riskClass}`}>
                          {arabicRisk(risk)}
                        </span>
                      </td>
                      <td>{alert.event || "—"}</td>
                      <td className="recommendation-cell">
                        {alert.recommendation || "لا توجد توصية مسجلة"}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <p className="chart-note">
        تعرض الصفحة التنبيهات المتاحة من الخادم، ولا تنشئ تنبيهات من مراقبة
        مباشرة للشبكة.
      </p>
    </main>
  );
}
