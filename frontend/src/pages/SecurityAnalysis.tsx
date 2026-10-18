
import { useMemo } from "react";
import type { SecurityAlert } from "../types";

type Props = {
alerts?: SecurityAlert[];
loading?: boolean;
};

export default function SecurityAnalysis({
alerts = [],
loading = false,
}: Props) {
const counts = useMemo(() => {
    return alerts.reduce(
    (result, alert) => {
        const risk = (alert.risk_level ?? "").toLowerCase();

        if (risk === "high") {
        result.high += 1;
        } else if (risk === "medium") {
        result.medium += 1;
        } else if (risk === "low") {
        result.low += 1;
        }

        result.failed += Number(alert.failed_attempts) || 0;

        return result;
    },
    { high: 0, medium: 0, low: 0, failed: 0 },
    );
}, [alerts]);

const total = counts.high + counts.medium + counts.low;

const metrics = [
    {
    label: "أحداث عالية الخطورة",
    value: counts.high,
    color: "danger",
    icon: "⚠",
    },
    {
    label: "أحداث متوسطة الخطورة",
    value: counts.medium,
    color: "medium",
    icon: "◈",
    },
    {
    label: "أحداث منخفضة الخطورة",
    value: counts.low,
    color: "safe",
    icon: "✓",
    },
    {
    label: "محاولات الدخول الفاشلة",
    value: counts.failed,
    color: "warning",
    icon: "⌕",
    },
];

const riskLevels = [
    { label: "عالية", value: counts.high, color: "#fb626b", className: "high" },
    { label: "متوسطة", value: counts.medium, color: "#f5b94c", className: "medium" },
    { label: "منخفضة", value: counts.low, color: "#3dd6a0", className: "low" },
];

return (
    <main className="page-container" dir="rtl">
    <header className="topbar">
        <div>
        <p className="eyebrow">SOC / SECURITY ANALYTICS</p>
        <h1>التحليل الأمني</h1>
        <p>تحليل مستويات الخطورة ومحاولات الدخول ضمن التنبيهات المتاحة.</p>
        </div>

        <span className="connection-badge">
        <span className={`status-dot ${loading ? "" : "online"}`} />
        {loading ? "جارٍ تحميل البيانات" : "تحليل السجلات"}
        </span>
    </header>

    <section>
        <div className="section-heading">
        <div>
            <h2>المؤشرات الأمنية</h2>
            <p>النتائج المحسوبة من التنبيهات التي استلمتها الواجهة.</p>
        </div>
        <span className="data-label">
            {loading ? "جارٍ التحميل" : `${alerts.length} سجل`}
        </span>
        </div>

        <div className="dashboard-grid">
        {metrics.map((metric) => (
            <article
            className={`stat-card ${metric.color}`}
            key={metric.label}
            >
            <div className="stat-top">
                <span>{metric.label}</span>
                <span className="stat-icon">{metric.icon}</span>
            </div>

            <strong>{loading ? "—" : metric.value}</strong>
            <small>حسب البيانات المستلمة من الخادم</small>
            </article>
        ))}
        </div>
    </section>

    <section className="analytics-section">
        <div className="section-heading">
        <div>
            <h2>تفاصيل مستويات الخطورة</h2>
            <p>مقارنة عدد التنبيهات حسب التصنيف الحالي.</p>
        </div>
        </div>

        <div className="analytics-grid">
        <article className="panel">
            <div className="panel-heading">
            <div>
                <h3>مقارنة المخاطر</h3>
                <p>عدد السجلات في كل مستوى</p>
            </div>
            <span className="panel-mark">01</span>
            </div>

            <div className="bar-chart">
            {riskLevels.map((item) => {
                const percentage =
                  total > 0 ? (item.value / total) * 100 : 0;

                return (
                <div key={item.label}>
                    <div className="bar-label">
                    <span>{item.label}</span>
                    <strong>
                        {loading
                        ? "—"
                        : `${item.value} (${Math.round(percentage)}%)`}
                    </strong>
                    </div>

                    <div className="bar-track">
                    <div
                        className={`bar-fill ${item.className}`}
                        style={{
                        width: `${loading ? 0 : percentage}%`,
                        }}
                    />
                    </div>
                </div>
                );
            })}
            </div>
        </article>

        <article className="panel">
            <div className="panel-heading">
            <div>
                <h3>ملخص مستويات الخطورة</h3>
                <p>توزيع التنبيهات بحسب التصنيف</p>
            </div>
            <span className="panel-mark">02</span>
            </div>

            <div className="risk-chart-layout">
            <div
                className="risk-donut"
                style={{
                background:
                    total > 0
                    ? `conic-gradient(
                          #fb626b 0% ${(counts.high / total) * 100}%,
                          #f5b94c ${(counts.high / total) * 100}% ${((counts.high + counts.medium) / total) * 100}%,
                          #3dd6a0 ${((counts.high + counts.medium) / total) * 100}% 100%
                        )`
                    : "#263448",
                }}
            >
                <div className="donut-center">
                <strong>{loading ? "—" : total}</strong>
                <span>سجل</span>
                </div>
            </div>

            <div className="risk-legend">
                {riskLevels.map((item) => (
                <div className="legend-row" key={item.label}>
                    <span className={`legend-dot ${item.className}`} />
                    <span>{item.label}</span>
                    <strong>{loading ? "—" : item.value}</strong>
                </div>
                ))}
            </div>
            </div>
        </article>
        </div>
    </section>

    <section className="alerts-section">
        <div className="section-heading">
        <div>
            <h2>محاولات الدخول المسجلة</h2>
            <p>السجلات المتاحة للمراجعة في الوقت الحالي.</p>
        </div>
        <span className="alert-counter">
            {loading ? "—" : alerts.length}
        </span>
        </div>

        <div className="panel">
        {loading ? (
            <div className="empty-state">جارٍ تحميل السجلات...</div>
        ) : alerts.length === 0 ? (
            <div className="empty-state">
            لا توجد سجلات متاحة للتحليل حاليًا.
            </div>
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
                </tr>
                </thead>

                <tbody>
                {alerts.slice(0, 10).map((alert, index) => {
                    const risk = (alert.risk_level ?? "").toLowerCase();

                    return (
                    <tr
                        key={`${alert.username}-${alert.ip_address}-${index}`}
                    >
                        <td>{alert.username || "غير معروف"}</td>
                        <td>
                        <code>{alert.ip_address || "—"}</code>
                        </td>
                        <td>{Number(alert.failed_attempts) || 0}</td>
                        <td>
                        <span
                            className={`risk ${
                            ["high", "medium", "low"].includes(risk)
                                ? risk
                                : ""
                            }`}
                        >
                            {risk === "high"
                            ? "عالية"
                            : risk === "medium"
                                ? "متوسطة"
                                : risk === "low"
                                ? "منخفضة"
                                : "غير محددة"}
                        </span>
                        </td>
                        <td>{alert.event || "—"}</td>
                    </tr>
                    );
                })}
                </tbody>
            </table>
            </div>
        )}
        </div>
    </section>

    <p className="chart-note">
        تعتمد النتائج على السجلات التي يوفرها الخادم. هذه الصفحة لا تراقب
        الشبكة مباشرة ولا تستخدم نموذج تعلم آلي مدرّب.
    </p>
    </main>
);
}
