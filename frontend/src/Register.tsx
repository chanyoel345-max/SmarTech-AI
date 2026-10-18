
import { useState, type FormEvent } from "react";
import {
  createUserWithEmailAndPassword,
  updateProfile,
} from "firebase/auth";
import { FirebaseError } from "firebase/app";
import { auth } from "./firebase";

type RegisterProps = {
  onRegister: () => void;
  onGoToLogin: () => void;
};

export default function Register({
  onRegister,
  onGoToLogin,
}: RegisterProps) {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");

    if (
      !name.trim() ||
      !email.trim() ||
      !password ||
      !confirmPassword
    ) {
      setError("يرجى تعبئة جميع الحقول.");
      return;
    }

    if (password.length < 6) {
      setError("كلمة المرور يجب أن تكون 6 أحرف على الأقل.");
      return;
    }

    if (password !== confirmPassword) {
      setError("كلمتا المرور غير متطابقتين.");
      return;
    }

    setBusy(true);

    try {
      const credential = await createUserWithEmailAndPassword(
        auth,
        email.trim(),
        password
      );

      await updateProfile(credential.user, {
        displayName: name.trim(),
      });

      onRegister();
    } catch (err) {
      const code = err instanceof FirebaseError ? err.code : "";

      const messages: Record<string, string> = {
        "auth/invalid-email": "صيغة البريد الإلكتروني غير صحيحة.",
        "auth/email-already-in-use":
          "هذا البريد مسجل مسبقًا. سجّلي الدخول بدلًا من ذلك.",
        "auth/weak-password":
          "اختاري كلمة مرور أقوى، من 6 أحرف على الأقل.",
        "auth/network-request-failed":
          "تعذر الاتصال بالإنترنت.",
        "auth/operation-not-allowed":
          "فعّلي Email/Password في إعدادات Firebase.",
        "auth/too-many-requests":
          "محاولات كثيرة. انتظري قليلًا ثم حاولي مجددًا.",
      };

      setError(
        messages[code] || "تعذر إنشاء الحساب. حاولي مرة أخرى."
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <main style={styles.page} dir="rtl">
      {/* قسم إنشاء الحساب */}
      <section style={styles.panel}>
        <div style={styles.brand}>
          <div style={styles.logo}>N</div>

          <div>
            <h1 style={styles.brandTitle}>SmarTech AI</h1>
            <p style={styles.brandSubtitle}>
              Smart Infrastructure Security
            </p>
          </div>
        </div>

        <div style={styles.heading}>
          <span style={styles.status}>
            <span style={styles.statusDot} />
            إنشاء حساب جديد
          </span>

          <h2 style={styles.title}>انضمي إلى SmarTech AI</h2>

          <p style={styles.description}>
            أنشئي حسابك للوصول إلى لوحة إدارة ومراقبة البنية التحتية التقنية.
          </p>
        </div>

        <form onSubmit={handleSubmit} style={styles.form}>
          <label htmlFor="register-name" style={styles.label}>
            الاسم الكامل
          </label>

          <input
            id="register-name"
            type="text"
            autoComplete="name"
            placeholder="أدخلي اسمك"
            value={name}
            onChange={(event) => setName(event.target.value)}
            style={styles.input}
            required
          />

          <label htmlFor="register-email" style={styles.label}>
            البريد الإلكتروني
          </label>

          <input
            id="register-email"
            type="email"
            autoComplete="email"
            placeholder="name@example.com"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            style={styles.input}
            required
          />

          <label htmlFor="register-password" style={styles.label}>
            كلمة المرور
          </label>

          <div style={styles.passwordWrapper}>
            <input
              id="register-password"
              type={showPassword ? "text" : "password"}
              autoComplete="new-password"
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

          <label htmlFor="confirm-password" style={styles.label}>
            تأكيد كلمة المرور
          </label>

          <input
            id="confirm-password"
            type={showPassword ? "text" : "password"}
            autoComplete="new-password"
            placeholder="أعيدي كتابة كلمة المرور"
            value={confirmPassword}
            onChange={(event) =>
              setConfirmPassword(event.target.value)
            }
            style={styles.input}
            minLength={6}
            required
          />

          {error && (
            <p role="alert" style={styles.error}>
              {error}
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
            {busy ? "جارٍ إنشاء الحساب..." : "إنشاء الحساب"}
          </button>
        </form>

        <div style={styles.loginText}>
          <span>لديك حساب بالفعل؟</span>

          <button
            type="button"
            style={styles.link}
            onClick={onGoToLogin}
          >
            تسجيل الدخول
          </button>
        </div>

        <div style={styles.securityNote}>
          <span>▣</span>
          <span>نظام مراقبة وإدارة تقنية المعلومات</span>
        </div>

        <p style={styles.footer}>
          SmarTech AI © 2026 — منصة ذكية لإدارة البنية التحتية
        </p>
      </section>

      {/* الجانب التعريفي */}
      <aside style={styles.side}>
        <div style={styles.grid} />

        <div style={styles.sideContent}>
          <div style={styles.icon}>⌘</div>

          <p style={styles.eyebrow}>
            INTELLIGENT IT OPERATIONS
          </p>

          <h2 style={styles.sideTitle}>
            بنية تحتية أذكى.
            <br />
            حماية أقوى.
          </h2>

          <p style={styles.sideDescription}>
            راقبي الأنظمة، وحلّلي الأحداث الأمنية، وتابعي حالة
            الشبكات والخوادم من مكان واحد.
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
    padding: "36px 32px",
  },

  brand: {
    display: "flex",
    alignItems: "center",
    gap: 14,
    marginBottom: 32,
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

  brandTitle: {
    margin: 0,
    fontSize: 24,
    letterSpacing: 1,
  },

  brandSubtitle: {
    margin: "5px 0 0",
    color: "#8493a9",
    fontSize: 11,
  },

  heading: {
    marginBottom: 20,
  },

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

  title: {
    fontSize: 28,
    margin: "18px 0 10px",
  },

  description: {
    color: "#9aa8bc",
    fontSize: 13,
    lineHeight: 1.9,
  },

  form: {
    display: "flex",
    flexDirection: "column",
    gap: 8,
  },

  label: {
    fontSize: 13,
    color: "#d4deeb",
    marginTop: 6,
  },

  input: {
    boxSizing: "border-box",
    width: "100%",
    padding: "12px 14px",
    borderRadius: 9,
    border: "1px solid #27364a",
    background: "#0d1524",
    color: "#f1f5f9",
    outline: "none",
    fontSize: 13,
    fontFamily: "inherit",
  },

  passwordWrapper: {
    display: "flex",
    alignItems: "center",
    borderRadius: 9,
    border: "1px solid #27364a",
    background: "#0d1524",
    overflow: "hidden",
  },

  passwordInput: {
    flex: 1,
    minWidth: 0,
    padding: "12px 14px",
    border: "none",
    outline: "none",
    background: "transparent",
    color: "#f1f5f9",
    fontSize: 13,
    fontFamily: "inherit",
  },

  showPassword: {
    padding: 10,
    border: "none",
    background: "transparent",
    color: "#67d9aa",
    cursor: "pointer",
    fontFamily: "inherit",
  },

  error: {
    color: "#ff8c8c",
    fontSize: 13,
    lineHeight: 1.7,
  },

  submit: {
    marginTop: 12,
    padding: 13,
    border: "1px solid #38b987",
    borderRadius: 9,
    background: "#16845e",
    color: "#ffffff",
    fontWeight: 700,
    fontSize: 14,
    fontFamily: "inherit",
    cursor: "pointer",
  },

  loginText: {
    display: "flex",
    justifyContent: "center",
    alignItems: "center",
    flexWrap: "wrap",
    gap: 8,
    color: "#9aa8bc",
    fontSize: 12,
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
    fontSize: 11,
    marginTop: 24,
  },

  footer: {
    marginTop: 24,
    textAlign: "center",
    color: "#687991",
    fontSize: 10,
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
  },

  sideContent: {
    position: "relative",
    maxWidth: 440,
  },

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

  eyebrow: {
    color: "#60d6a3",
    fontSize: 11,
    letterSpacing: 2,
  },

  sideTitle: {
    fontSize: 38,
    lineHeight: 1.5,
    margin: "18px 0",
  },

  sideDescription: {
    color: "#9aa9bd",
    lineHeight: 2,
    fontSize: 14,
  },

  features: {
    display: "grid",
    gap: 22,
    marginTop: 36,
  },

  feature: {
    display: "flex",
    gap: 16,
    alignItems: "center",
  },

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
