
import { useMemo, useState } from "react";
import type { SecurityAlert } from "../types";

type Props = {
alerts: SecurityAlert[];
loading: boolean;
};

export default function LogAnalysis({ alerts, loading }: Props) {
const [search, setSearch] = useState("");
const [riskFilter, setRiskFilter] = useState("all");

const logs = useMemo(() => {
    const query = search.trim().toLowerCase();

    return alerts.filter((alert) => {
    const searchable = [
        alert.username,
        alert.ip_address,
        alert.event,
        alert.timestamp,
        alert.risk_level,
    ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();

    const risk = (alert.risk_level ?? "").toLowerCase();

    return (
        searchable.includes(query) &&
        (riskFilter === "all" || risk === riskFilter)
    );
    });
}, [alerts, search, riskFilter]);

return (
    <main className="page-container" dir="rtl">
    <header className="topbar">
        <div>
        <p className="eyebrow">SOC / LOG ANALYSIS</p>
        <h1>تحليل السجلات</h1>
        <p>البحث في الأحداث المتاحة ومراجعة تفاصيلها ومستوى خطورتها.</p>
        </div>
        <span className="data-label">
        {loading ? "جارٍ التحميل" : `${logs.length} سجل`}
        </span>
    </header>

    <section className="dashboard-grid">
        <article className="stat-card">
        <div className="stat-top"><span>إجمالي السجلات</span><span className="stat-icon">▤</span></div>
        <strong>{loading ? "—" : alerts.length}</strong>
        <small>السجلات التي أعادها الخادم</small>
        </article>
        <article className="stat-card danger">
        <div className="stat-top"><span>خطورة عالية</span><span className="stat-icon">⚠</span></div>
        <strong>{loading ? "—" : alerts.filter((a) => a.risk_level.toLowerCase() === "high").length}</strong>
        <small>حسب التصنيف المتاح</small>
        </article>
        <article className="stat-card medium">
        <div className="stat-top"><span>خطورة متوسطة</span><span className="stat-icon">◈</span></div>
        <strong>{loading ? "—" : alerts.filter((a) => a.risk_level.toLowerCase() === "medium").length}</strong>
        <small>حسب التصنيف المتاح</small>
        </article>
        <article className="stat-card safe">
        <div className="stat-top"><span>خطورة منخفضة</span><span className="stat-icon">✓</span></div>
        <strong>{loading ? "—" : alerts.filter((a) => a.risk_level.toLowerCase() === "low").length}</strong>
        <small>حسب التصنيف المتاح</small>
        </article>
    </section>

    <section className="panel">
        <div className="section-heading">
        <div>
            <h2>البحث في السجلات</h2>
            <p>ابحثي بالنص أو اسم المستخدم أو عنوان IP.</p>
        </div>
        </div>

        <div className="content-grid">
        <div>
            <label htmlFor="log-search">كلمة البحث</label>
            <input
            id="log-search"
            type="search"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="اكتبي كلمة للبحث..."
            />
        </div>
        <div>
            <label htmlFor="log-risk-filter">مستوى الخطورة</label>
            <select
            id="log-risk-filter"
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
            <h3>سجل الأحداث</h3>
            <p>تفاصيل السجلات المطابقة للفلاتر.</p>
        </div>
        <span className="panel-mark">{loading ? "—" : logs.length}</span>
        </div>

        {loading ? (
        <div className="empty-state">جارٍ تحميل السجلات...</div>
        ) : logs.length === 0 ? (
        <div className="empty-state">لا توجد سجلات مطابقة.</div>
        ) : (
        <div className="table-container">
            <table>
            <thead>
                <tr>
                <th>التوقيت</th>
                <th>المستخدم</th>
                <th>عنوان IP</th>
                <th>الحدث</th>
                <th>المحاولات الفاشلة</th>
                <th>الخطورة</th>
                </tr>
            </thead>
            <tbody>
                {logs.map((log, index) => {
                const risk = (log.risk_level ?? "").toLowerCase();
                const riskClass = ["high", "medium", "low"].includes(risk)
                    ? risk
                    : "";

                return (
                    <tr key={`${log.username}-${log.ip_address}-${index}`}>
                    <td>{log.timestamp || "غير متوفر"}</td>
                    <td>{log.username || "غير معروف"}</td>
                    <td><code>{log.ip_address || "—"}</code></td>
                    <td>{log.event || "حدث مسجل"}</td>
                    <td>{Number(log.failed_attempts) || 0}</td>
                    <td>
                        <span className={`risk ${riskClass}`}>
                        {risk === "high"
                            ? "عالية"
                            : risk === "medium"
                            ? "متوسطة"
                            : risk === "low"
                                ? "منخفضة"
                                : "غير محددة"}
                        </span>
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
        تعرض الصفحة الحقول المتاحة في بيانات الخادم فقط. إذا لم يوفر الخادم
        توقيت الحدث، فسيظهر على أنه غير متوفر.
    </p>
    </main>
);
}
