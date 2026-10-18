
import { useCallback, useEffect, useState } from "react";
import { auth } from "../firebase";

type Props = {
apiBase: string;
};

type Status = "checking" | "online" | "offline";

export default function SystemStatus({ apiBase }: Props) {
const [status, setStatus] = useState<Status>("checking");
const [lastCheck, setLastCheck] = useState<string>("لم يتم الفحص بعد");
const [errorMessage, setErrorMessage] = useState("");

const checkConnection = useCallback(async () => {
    setStatus("checking");
    setErrorMessage("");

    try {
    const user = auth.currentUser;

    if (!user) {
        throw new Error("يجب تسجيل الدخول أولًا.");
    }

    const token = await user.getIdToken();

    const response = await fetch(`${apiBase}/api/summary`, {
        headers: {
        Authorization: `Bearer ${token}`,
        },
    });

    if (!response.ok) {
        throw new Error(`استجاب الخادم بالرمز ${response.status}`);
    }

    await response.json();

    setStatus("online");
    setLastCheck(new Date().toLocaleString("ar-SA"));
    } catch (error) {
    setStatus("offline");
    setLastCheck(new Date().toLocaleString("ar-SA"));

    setErrorMessage(
        error instanceof Error
        ? error.message
        : "تعذر الاتصال بالخادم."
    );
    }
}, [apiBase]);

useEffect(() => {
    void checkConnection();
}, [checkConnection]);

const statusText =
    status === "online"
    ? "متصل"
    : status === "offline"
        ? "غير متصل"
        : "جارٍ الفحص";

return (
    <main className="page-container" dir="rtl">
    <header className="topbar">
        <div>
        <p className="eyebrow">SOC / SYSTEM STATUS</p>
        <h1>حالة النظام</h1>
        <p>فحص اتصال الواجهة بالخادم وعرض نتيجة آخر فحص.</p>
        </div>

        <button
        type="button"
        className="primary-button"
        onClick={() => void checkConnection()}
        disabled={status === "checking"}
        >
        {status === "checking" ? "جارٍ الفحص..." : "إعادة الفحص"}
        </button>
    </header>

    <section className="dashboard-grid">
        <article className="stat-card">
        <div className="stat-top">
            <span>حالة اتصال الخادم</span>
            <span className="stat-icon">●</span>
        </div>
        <strong>{statusText}</strong>
        <small>نتيجة آخر طلب إلى واجهة API</small>
        </article>

        <article className="stat-card">
        <div className="stat-top">
            <span>عنوان API</span>
            <span className="stat-icon">⌘</span>
        </div>
        <p dir="ltr" style={{ overflowWrap: "anywhere" }}>
            {apiBase}
        </p>
        <small>العنوان المستخدم للاتصال</small>
        </article>

        <article className="stat-card">
        <div className="stat-top">
            <span>آخر فحص</span>
            <span className="stat-icon">◷</span>
        </div>
        <p>{lastCheck}</p>
    <small>وقت الفحص في المتصفح</small>
        </article>
    </section>

    <section className="panel">
        <div className="panel-heading">
        <div>
            <h3>تفاصيل الاتصال</h3>
            <p>نتيجة فحص نقطة ملخص البيانات.</p>
        </div>

        <span
            className={`risk ${
            status === "online"
                ? "low"
                : status === "offline"
                ? "high"
                : "medium"
            }`}
        >
            {statusText}
        </span>
        </div>

        {status === "checking" && (
        <div className="notice-panel">
            جارٍ التحقق من اتصال الخادم...
        </div>
        )}

        {status === "online" && (
        <div className="notice-panel">
            نجح الاتصال بالخادم وتمت قراءة استجابة واجهة API.
        </div>
        )}

        {status === "offline" && (
        <div className="error-banner" role="alert">
            تعذر الاتصال بالخادم: {errorMessage}
        </div>
        )}

        <p className="chart-note">
        نجاح الفحص يؤكد استجابة نقطة API فقط، ولا يثبت أن جميع أجهزة
        الشبكة أو خدمات البنية التحتية تعمل.
        </p>
    </section>
    </main>
);
}
