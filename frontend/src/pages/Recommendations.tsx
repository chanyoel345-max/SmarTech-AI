
import { useMemo, useState } from "react";
import type { SecurityAlert } from "../types";

type Props = {
alerts?: SecurityAlert[];
loading?: boolean;
};

export default function Recommendations({
alerts = [],
loading = false,
}: Props) {
const [filter, setFilter] = useState("all");

const recommendations = useMemo(() => {
    return alerts
    .filter((alert) => {
        const risk = (alert.risk_level ?? "").toLowerCase();

        if (filter === "all") return true;
        return risk === filter;
    })
    .map((alert, index) => ({
        ...alert,
        id: `${alert.username}-${alert.ip_address}-${index}`,
        risk: (alert.risk_level ?? "").toLowerCase(),
        attempts: Number(alert.failed_attempts) || 0,
        recommendation:
        alert.recommendation ||
        "راجعي سجل الحدث، وتحققي من هوية المستخدم، وطبّقي سياسة الوصول المناسبة.",
    }))
    .sort((a, b) => {
        const riskOrder: Record<string, number> = {
        high: 3,
        medium: 2,
        low: 1,
        };

        return (
        (riskOrder[b.risk] ?? 0) - (riskOrder[a.risk] ?? 0) ||
        b.attempts - a.attempts
        );
    });
}, [alerts, filter]);

function translateRisk(risk: string) {
    switch (risk) {
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
    <div className="page-content" dir="rtl">
    <header className="page-header">
        <div>
        <span className="eyebrow">SECURITY RECOMMENDATIONS</span>
        <h1>التوصيات الأمنية</h1>
        <p>
            إجراءات مقترحة لمراجعة التنبيهات وتقليل المخاطر الأمنية.
        </p>
        </div>
    </header>

    <section className="section-block">
        <div className="section-title">
        <div>
            <h2>قائمة التوصيات</h2>
            <p>
            رتّبت النتائج حسب مستوى الخطورة، ثم عدد محاولات الدخول.
            </p>
        </div>

        <select
            value={filter}
            onChange={(event) => setFilter(event.target.value)}
            aria-label="تصفية التوصيات حسب مستوى الخطورة"
        >
            <option value="all">كل المستويات</option>
            <option value="high">عالية</option>
            <option value="medium">متوسطة</option>
            <option value="low">منخفضة</option>
        </select>
        </div>

        {loading ? (
        <div className="empty-state">
            <p>جارٍ تحميل البيانات...</p>
        </div>
        ) : recommendations.length === 0 ? (
        <div className="empty-state">
            <p>لا توجد توصيات مرتبطة بالتنبيهات الحالية.</p>
        </div>
        ) : (
        <div className="recommendation-list">
            {recommendations.map((item, index) => (
            <article className="recommendation-item" key={item.id}>
                <span className="priority-number">
                {String(index + 1).padStart(2, "0")}
                </span>

                <div className="recommendation-body">
                <div className="recommendation-heading">
                    <strong>
                    {item.username || "مستخدم غير معروف"}
                    </strong>

                    <span className={`risk-pill ${item.risk}`}>
                    {translateRisk(item.risk)}
                    </span>
                </div>

                <p>
                    عنوان IP:{" "}
                    <code dir="ltr">
                    {item.ip_address || "غير متوفر"}
                    </code>
                </p>

                <p>
                    محاولات الدخول المسجلة: {item.attempts}
                </p>

                <div className="recommendation-advice">
                    <strong>الإجراء المقترح</strong>
                    <p>{item.recommendation}</p>
                </div>
                </div>
            </article>
            ))}
        </div>
        )}
    </section>

<section className="panel section-block">
        <h2>إرشادات عامة</h2>
        <ul>
        <li>تحققي من سجلات الدخول قبل اتخاذ أي إجراء.</li>
        <li>راجعي صلاحيات المستخدمين وفق مبدأ أقل صلاحية.</li>
        <li>استخدمي المصادقة متعددة العوامل للحسابات المهمة.</li>
        <li>وثّقي الإجراءات ونتائج المراجعة.</li>
        </ul>

        <p className="demo-notice">
        التوصيات إرشادية فقط؛ لا يُنفَّذ حظر الحسابات أو عناوين IP تلقائيًا.
        </p>
    </section>
    </div>
);
}
