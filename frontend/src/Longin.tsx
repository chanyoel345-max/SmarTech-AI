import { useState, type FormEvent } from "react";
import {
createUserWithEmailAndPassword,
sendPasswordResetEmail,
signInWithEmailAndPassword,
} from "firebase/auth";
import { FirebaseError } from "firebase/app";
import { auth } from "./firebase";

interface LoginProps {
onLogin: () => void;
onGoToRegister: () => void;
}
type Mode = "login" | "register" | "reset";

export default function Login({ onLogin, onGoToRegister }: LoginProps) {
const [email, setEmail] = useState("");
const [password, setPassword] = useState("");
const [showPassword, setShowPassword] = useState(false);
const [mode, setMode] = useState<Mode>("login");
const [error, setError] = useState("");
const [message, setMessage] = useState("");
const [busy, setBusy] = useState(false);

async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setMessage("");

    const cleanEmail = email.trim();

    if (!cleanEmail) {
    setError("أدخلي البريد الإلكتروني.");
    return;
    }

    if (mode !== "reset" && password.length < 6) {
    setError("كلمة المرور يجب أن تكون 6 أحرف على الأقل.");
    return;
    }

    setBusy(true);

    try {
    if (mode === "register") {
        await createUserWithEmailAndPassword(auth, cleanEmail, password);
        // Firebase ينشئ الحساب ويسجل دخوله تلقائيًا.
        onLogin();
    } else if (mode === "login") {
        await signInWithEmailAndPassword(auth, cleanEmail, password);
        onLogin();
    } else {
        await sendPasswordResetEmail(auth, cleanEmail);
        setMessage(
        "أرسلنا رابط استعادة كلمة المرور إلى بريدك إذا كان مسجلًا لدينا.",
        );
    }
    } catch (err) {
    const code = err instanceof FirebaseError ? err.code : "";

    const messages: Record<string, string> = {
        "auth/invalid-email": "صيغة البريد الإلكتروني غير صحيحة.",
        "auth/user-not-found": "البريد الإلكتروني أو كلمة المرور غير صحيحة.",
        "auth/wrong-password": "البريد الإلكتروني أو كلمة المرور غير صحيحة.",
        "auth/invalid-credential":
        "البريد الإلكتروني أو كلمة المرور غير صحيحة.",
        "auth/email-already-in-use":
        "هذا البريد مسجل مسبقًا. جرّبي تسجيل الدخول.",
        "auth/weak-password": "اختاري كلمة مرور أقوى، من 6 أحرف على الأقل.",
        "auth/too-many-requests":
        "محاولات كثيرة. انتظري قليلًا ثم حاولي مجددًا.",
        "auth/network-request-failed": "تعذر الاتصال. تحققي من الإنترنت.",
        "auth/operation-not-allowed":
        "طريقة البريد وكلمة المرور غير مفعّلة في Firebase.",
    };

    setError(
        messages[code] ||
        "تعذر إكمال العملية. تحققي من البيانات وحاولي مجددًا.",
    );
    } finally {
    setBusy(false);
    }
}

const title =
    mode === "register"
    ? "إنشاء حساب جديد"
    : mode === "reset"
        ? "استعادة كلمة المرور"
        : "مرحبًا بعودتك";

return (
    <main style={styles.page} dir="rtl">
    <section style={styles.panel}>
        <div style={styles.brand}>
        <div style={styles.logo}>N</div>
        <div>
            <h1 style={styles.brandTitle}>NexusAI</h1>
            <p style={styles.brandSubtitle}>Smart Infrastructure Security</p>
        </div>
        </div>

        <div style={styles.heading}>
        <span style={styles.status}>
            <span style={styles.statusDot} />
            بوابة الوصول الآمن
        </span>

        <h2 style={styles.title}>{title}</h2>
        <p style={styles.description}>
            {mode === "register"
            ? "أنشئي حسابك للوصول إلى لوحة مراقبة البنية التحتية."
            : mode === "reset"
                ? "أدخلي بريدك الإلكتروني لإرسال رابط استعادة كلمة المرور."
                : "سجّلي الدخول للوصول إلى لوحة مراقبة البنية التحتية التقنية."}
        </p>
        </div>

        <form onSubmit={handleSubmit} style={styles.form}>
        <label htmlFor="email" style={styles.label}>
            البريد الإلكتروني
        </label>
        <input
            id="email"
            type="email"
            autoComplete="email"
            placeholder="name@example.com"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            style={styles.input}
            required
        />

        {mode !== "reset" && (
            <>
            <label htmlFor="password" style={styles.label}>
                كلمة المرور
            </label>
            <div style={styles.passwordWrapper}>
                <input
                id="password"
                type={showPassword ? "text" : "password"}
                autoComplete={
                    mode === "register" ? "new-password" : "current-password"
                }
                placeholder="6 أحرف على الأقل"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                style={styles.passwordInput}
                minLength={6}
                required
                />
                <button
                type="button"
                onClick={() => setShowPassword((value) => !value)}
                style={styles.showPassword}
                >
                {showPassword ? "إخفاء" : "عرض"}
                </button>
            </div>
            </>
        )}

        {error && (
            <p role="alert" style={styles.error}>
            {error}
            </p>
        )}

        {message && (
            <p role="status" style={styles.success}>
            {message}
            </p>
        )}

        <button
            type="submit"
            style={{
            ...styles.submit,
            opacity: busy ? 0.7 : 1,
            }}
            disabled={busy}
        >
            {busy
            ? "جارٍ المعالجة..."
            : mode === "register"
                ? "إنشاء الحساب"
                : mode === "reset"
                ? "إرسال رابط الاستعادة"
                : "تسجيل الدخول"}
            {!busy && mode !== "reset" && <span> ← </span>}
        </button>
        </form>

        <div style={styles.links}>
        {mode === "login" && (
            <>
            <button
                type="button"
                style={styles.link}
                onClick={() => {
                setMode("register");
                setError("");
                setMessage("");
                }}
            >
                إنشاء حساب جديد
            </button>
            <button
                type="button"
                style={styles.link}
                onClick={() => {
                setMode("reset");
                setError("");
                setMessage("");
                }}
            >
                نسيت كلمة المرور؟
            </button>
            </>
        )}

        {mode !== "login" && (

            <button
            type="button"
            style={styles.link}
            onClick={() => {
                setMode("login");
                setError("");
                setMessage("");
            }}
            >
            العودة إلى تسجيل الدخول
            </button>

        )}
        <button
type="button"
className="forgot-password"
onClick={onGoToRegister}
>
إنشاء حساب جديد
</button>
</div>
        <div style={styles.securityNote}>
        <span>▣</span>
        <span>نظام مراقبة وإدارة تقنية المعلومات</span>
        </div>

        <p style={styles.footer}>
        NexusAI © 2026 — منصة ذكية لإدارة البنية التحتية
        </p>
    </section>

    <aside style={styles.side}>
        <div style={styles.grid} />
        <div style={styles.sideContent}>
        <div style={styles.icon}>⌘</div>
        <p style={styles.eyebrow}>INTELLIGENT IT OPERATIONS</p>
        <h2 style={styles.sideTitle}>
            بنية تحتية أذكى.
            <br />
            حماية أقوى.
        </h2>
        <p style={styles.sideDescription}>
            راقب الأنظمة، وحلّل الأحداث الأمنية، وتابع حالة الشبكات والخوادم من
            مكان واحد.
        </p>

        <div style={styles.features}>
            <div style={styles.feature}>
            <span style={styles.featureIcon}>◈</span>
            <div>
                <strong>مراقبة الأنظمة</strong>
                <p>متابعة حالة الأجهزة والخدمات</p>
            </div>
            </div>
            <div style={styles.feature}>
            <span style={styles.featureIcon}>⌁</span>
            <div>
                <strong>تحليل أمني</strong>
                <p>عرض الأحداث ومحاولات الدخول المشبوهة</p>
            </div>
            </div>
            <div style={styles.feature}>
            <span style={styles.featureIcon}>▥</span>
            <div>
                <strong>إدارة مركزية</strong>
                <p>لوحة واحدة لمعلومات البنية التحتية</p>
            </div>
            </div>
        </div>
        </div>
    </aside>
    </main>
);
}

const styles: Record<string, React.CSSProperties> = {
page: {
    minHeight: "100vh",
    display: "grid",
    gridTemplateColumns: "1fr 1fr",
    background: "#080d18",
    color: "#e8eef8",
    fontFamily: "Tahoma, Arial, sans-serif",
},
panel: {
    width: "100%",
    maxWidth: 480,
    boxSizing: "border-box",
    margin: "auto",
    padding: "48px 32px",
},
brand: {
    display: "flex",
    alignItems: "center",
    gap: 14,
    marginBottom: 54,
},
logo: {
    width: 48,
    height: 48,
    display: "grid",
    placeItems: "center",
    borderRadius: 14,
    background: "#122b27",
    border: "1px solid #286b55",
    color: "#55e6a5",
    fontSize: 27,
    fontWeight: 800,
},
brandTitle: { margin: 0, fontSize: 24, letterSpacing: 1 },
brandSubtitle: { margin: "5px 0 0", color: "#8493a9", fontSize: 11 },
heading: { marginBottom: 30 },
status: {
    display: "inline-flex",
    alignItems: "center",
    gap: 8,
    padding: "8px 12px",
    borderRadius: 20,
    border: "1px solid #25443d",
    color: "#65d9a6",
    fontSize: 12,
},
statusDot: {
    width: 7,
    height: 7,
    borderRadius: "50%",
    background: "#55e6a5",
},
title: { fontSize: 30, margin: "22px 0 10px" },
description: { color: "#9aa8bc", fontSize: 14, lineHeight: 1.9 },
form: { display: "flex", flexDirection: "column", gap: 12 },
label: { fontSize: 13, color: "#d4deeb", marginTop: 8 },
input: {
    boxSizing: "border-box",
    width: "100%",
    padding: "15px 14px",
    borderRadius: 10,
    border: "1px solid #27364a",
    background: "#0d1524",
    color: "#f1f5f9",
    outline: "none",
    fontSize: 14,
},
passwordWrapper: {
    display: "flex",
    alignItems: "center",
    borderRadius: 10,
    border: "1px solid #27364a",
    background: "#0d1524",
    overflow: "hidden",
},
passwordInput: {
    flex: 1,
    minWidth: 0,
    padding: "15px 14px",
    border: "none",
    outline: "none",
    background: "transparent",
    color: "#f1f5f9",
    fontSize: 14,
},
showPassword: {
    padding: 10,
    border: "none",
    background: "transparent",
    color: "#67d9aa",
    cursor: "pointer",
},
error: { color: "#ff8c8c", fontSize: 13 },
success: { color: "#65d9a6", fontSize: 13, lineHeight: 1.8 },
submit: {
    marginTop: 12,
    padding: 15,
    border: "1px solid #38b987",
    borderRadius: 10,
    background: "#16845e",
    color: "#ffffff",
    fontWeight: 700,
    fontSize: 15,
    cursor: "pointer",
},
links: {
    display: "flex",
    flexWrap: "wrap",
    justifyContent: "space-between",
    gap: 12,
    marginTop: 18,
},
link: {
    border: "none",
    background: "transparent",
    color: "#67d9aa",
    cursor: "pointer",
    fontFamily: "inherit",
    fontSize: 13,
    padding: 4,
},
securityNote: {
    display: "flex",
    justifyContent: "center",
    gap: 10,
    color: "#91a2b8",
    fontSize: 12,
    marginTop: 30,
},
footer: {
    marginTop: 34,
    textAlign: "center",
    color: "#687991",
    fontSize: 11,
    lineHeight: 1.8,
},
side: {
    position: "relative",
    overflow: "hidden",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    padding: 48,
    boxSizing: "border-box",
    borderRight: "1px solid #1c2a3c",
    background:
    "radial-gradient(ellipse at 50% 35%, #142b2b 0%, #0b1421 55%, #080d18 100%)",
},
grid: {
    position: "absolute",
    inset: 0,
    opacity: 0.13,
    backgroundImage:
    "linear-gradient(#4e9e84 1px, transparent 1px), linear-gradient(90deg, #4e9e84 1px, transparent 1px)",
    backgroundSize: "38px 38px",
    maskImage: "linear-gradient(to bottom, black, transparent 90%)",
},
sideContent: { position: "relative", maxWidth: 440 },
icon: {
    display: "grid",
    placeItems: "center",
    width: 72,
    height: 72,
    borderRadius: 20,
    border: "1px solid #285448",
    background: "#112923",
    color: "#62e6ad",
    fontSize: 42,
    marginBottom: 30,
},
eyebrow: { color: "#60d6a3", fontSize: 11, letterSpacing: 2 },
sideTitle: { fontSize: 38, lineHeight: 1.5, margin: "18px 0" },
sideDescription: { color: "#9aa9bd", lineHeight: 2, fontSize: 14 },
features: { display: "grid", gap: 22, marginTop: 36 },
feature: { display: "flex", gap: 16, alignItems: "center" },
featureIcon: {
    display: "grid",
    placeItems: "center",
    minWidth: 42,
    height: 42,
    borderRadius: 12,
    background: "#142a29",
    color: "#5de2a8",
    fontSize: 22,
},
};
