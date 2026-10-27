import { useCallback, useEffect, useState, type FormEvent } from "react";

import { onAuthStateChanged, signOut } from "firebase/auth";

import { auth } from "./firebase";

import Login from "./Longin";

import Register from "./Register";

import Overview from "./pages/Overview";

import Alerts from "./pages/Alerts";

import SecurityAnalysis from "./pages/SecurityAnalysis";

import Recommendations from "./pages/Recommendations";

import LogAnalysis from "./pages/LogAnalysis";

import SystemStatus from "./pages/SystemStatus";

import type { Summary, SecurityAlert, PageId } from "./types";

import "./App.css";

const API_BASE = (

  import.meta.env.VITE_API_URL || "https://smartech-ai.onrender.com"

).replace(/\/+$/, "");

const navigation: { id: PageId | "ip-search"; label: string }[] = [

  { id: "overview", label: "نظرة عامة" },

  { id: "ip-search", label: "تحليل عنوان IP" },

  { id: "analysis", label: "تحليل الأمن" },

  { id: "alerts", label: "التنبيهات" },

  { id: "recommendations", label: "التوصيات" },

  { id: "logs", label: "تحليل السجلات" },

  { id: "status", label: "حالة النظام" },

];

type IpEvent = Record<string, unknown> & {

  timestamp?: string;

  username?: string;

  source_ip?: string;

  event_type?: string;

  risk_level?: string;

  recommendation?: string;

  is_failed_login?: boolean;

  failed_attempts?: number | string;

};

type IpAnalysisResult = {

  ip_address: string;

  found: boolean;

  total_events: number;

  failed_login_events: number;

  failed_attempts_recorded: number | null;

  rows_with_attempt_counts: number;

  risk_level: string;

  usernames: string[];

  events: IpEvent[];

  analysis_basis: string;

  risk_note: string;

  attempts_note: string;

  message: string;

};

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function firstPresent(row: Record<string, unknown>, ...keys: string[]): unknown {
  for (const key of keys) {
    const value = row[key];
    if (value === undefined || value === null) continue;
    const text = String(value).trim();
    if (!text || /^(n\/a|na|none|unknown)$/i.test(text)) continue;
    return value;
  }
  return "";
}

function textValue(value: unknown): string {
  if (typeof value === "string" || typeof value === "number") {
    return String(value).trim();
  }
  return "";
}

function parseCount(value: unknown): number | null {
  if (value === null || value === undefined || String(value).trim() === "") return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) && Number.isInteger(parsed) && parsed >= 0 ? parsed : null;
}

function splitAccountNames(value: unknown): string[] {
  if (Array.isArray(value)) return value.flatMap((item) => splitAccountNames(item));

  const raw = textValue(value);
  if (
    !raw ||
    /^حسابات متعددة$/i.test(raw) ||
    /\b\d+\s+distinct\s+accounts?\b/i.test(raw)
  ) return [];

  return raw
    .split(/[,;،]+/)
    .map((item) => item.trim())
    .filter((item) => {
      if (!item) return false;
      if (/^(unknown|n\/a|none|غير معروف|غير محدد|حسابات متعددة)$/i.test(item)) return false;
      if (/\bdistinct\s+accounts?\b/i.test(item)) return false;
      return true;
    });
}

function normalizeIpEvent(value: unknown): IpEvent {
  const row = asRecord(value);
  const timestamp = textValue(firstPresent(
    row,
    "timestamp", "Timestamp", "start_time", "startTime", "StartTime",
    "first_seen", "first_seen_utc", "time", "TimeCreated", "start",
  ));

  const rawUsername = firstPresent(
    row, "username", "user", "User", "TargetUserName", "account", "Accounts",
  );
  const accounts = splitAccountNames(rawUsername);
  const usernameText = textValue(rawUsername);
  const username = /\bdistinct\s+accounts?\b/i.test(usernameText)
    ? "حسابات متعددة"
    : accounts.length > 0
      ? accounts.join("، ")
      : usernameText;

  const eventType = textValue(firstPresent(
    row, "event_type", "title", "Title", "alert_title", "event",
    "Event Type", "RuleName", "RuleID", "EventID", "action",
  )) || "حدث غير معروف";

  const rawRisk = textValue(firstPresent(
    row, "risk_level", "risk", "Risk Level", "severity", "Severity",
  ));
  const normalizedRisk = /^(critical|high|عالي|عالية|مرتفع|مرتفعة)$/i.test(rawRisk)
    ? "High"
    : /^(medium|moderate|متوسط|متوسطة)$/i.test(rawRisk)
      ? "Medium"
      : /^(low|منخفض|منخفضة)$/i.test(rawRisk)
        ? "Low"
        : rawRisk || "Unknown";

  const count = parseCount(firstPresent(
    row, "failed_attempts", "failed_attempt_count", "Count", "count", "Failed Attempts",
  ));
  const eventId = textValue(firstPresent(row, "EventID", "event_id", "EventIDs", "event_ids"));
  const successEvent = /successful\s+(logon|login)|نجاح\s+تسجيل\s+الدخول/i.test(eventType);
  const inferredFailed = !successEvent && (
    /failed\s+(logon|login)|repeated\s+failed|فشل\s+تسجيل\s+الدخول/i.test(eventType) ||
    /^4625$/.test(eventId)
  );
  const explicitFailed = row.is_failed_login;

  return {
    ...row,
    timestamp: timestamp || "",
    username: username || "غير معروف",
    source_ip: textValue(firstPresent(
      row, "source_ip", "SourceIP", "ip_address", "IpAddress", "ip", "Source IP",
    )),
    event_type: eventType,
    risk_level: normalizedRisk,
    recommendation: textValue(firstPresent(
      row, "recommendation", "Recommendation", "action_recommendation",
    )),
    failed_attempts: count === null ? undefined : count,
    is_failed_login: typeof explicitFailed === "boolean" ? explicitFailed : inferredFailed,
  };
}

function normalizeIpAnalysisResult(value: unknown): IpAnalysisResult {
  const body = asRecord(value);
  const events = Array.isArray(body.events) ? body.events.map(normalizeIpEvent) : [];
  const usernames = [...new Set([
    ...splitAccountNames(body.usernames),
    ...events.flatMap((item) => splitAccountNames(item.username)),
  ])];
  const totalEvents = parseCount(body.total_events) ?? events.length;
  const failedEvents = parseCount(body.failed_login_events) ??
    events.filter((item) => item.is_failed_login).length;

  let attempts = parseCount(body.failed_attempts_recorded);
  let attemptsNote = textValue(body.attempts_note);
  if (attempts === null) {
    const knownCounts = events
      .filter((item) => item.is_failed_login)
      .map((item) => parseCount(item.failed_attempts))
      .filter((item): item is number => item !== null);
    if (knownCounts.length > 0) {
      // Alert counts can overlap; use the highest individual alert count, not their sum.
      attempts = Math.max(...knownCounts);
      attemptsNote = "هذا أكبر عدد مسجل في تنبيه واحد مرتبط بمحاولات الدخول الفاشلة؛ لم نجمع التنبيهات المتداخلة لتجنب العد المزدوج.";
    }
  }

  const riskRank: Record<string, number> = { Unknown: 0, Low: 1, Medium: 2, High: 3, Critical: 3 };
  const inferredRisk = events.reduce((best, item) => {
    const current = item.risk_level || "Unknown";
    return (riskRank[current] ?? 0) > (riskRank[best] ?? 0) ? current : best;
  }, "Unknown");

  return {
    ip_address: textValue(body.ip_address),
    found: typeof body.found === "boolean" ? body.found : events.length > 0,
    total_events: totalEvents,
    failed_login_events: failedEvents,
    failed_attempts_recorded: attempts,
    rows_with_attempt_counts: parseCount(body.rows_with_attempt_counts) ?? 0,
    risk_level: textValue(body.risk_level) || inferredRisk,
    usernames,
    events,
    analysis_basis: textValue(body.analysis_basis) || "سجلات الأمان المتاحة للخادم فقط",
    risk_note: textValue(body.risk_note) || "مستوى الخطورة مؤشر للفرز الأولي وليس دليلًا قاطعًا على وقوع هجوم.",
    attempts_note: attemptsNote || "قد تشير عدة تنبيهات إلى الأحداث نفسها؛ لا يُعد عدد التنبيهات بالضرورة عدد محاولات فريدة.",
    message: textValue(body.message) || (events.length
      ? "عُثر على أحداث مطابقة في السجلات المتاحة."
      : "لم يُعثر على أحداث مطابقة في السجلات المتاحة."),
  };
}

function formatTimestamp(value?: string): string {
  const timestamp = (value || "").trim();
  if (!timestamp || /^(n\/a|na|unknown)$/i.test(timestamp)) return "غير متاح";
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) return timestamp;
  return new Intl.DateTimeFormat("ar-SA-u-ca-gregory", {
    year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
  }).format(date);
}

function displayEventTitle(value?: string): string {
  const title = (value || "").trim();
  const translations: Record<string, string> = {
    "Multiple accounts targeted from one IP": "استهداف عدة حسابات من عنوان IP واحد",
    "Successful logon after repeated failures": "تسجيل دخول ناجح بعد محاولات فاشلة متكررة",
    "Repeated failed logons from one IP": "تكرار محاولات تسجيل الدخول الفاشلة من عنوان IP واحد",
    "Windows account lockout observed": "رصد قفل حساب Windows",
  };
  return translations[title] || title || "حدث غير معروف";
}

function displayRisk(value?: string): string {
  switch ((value || "").toLowerCase()) {
    case "high":
    case "critical":
      return "مرتفعة";
    case "medium":
      return "متوسطة";
    case "low":
      return "منخفضة";
    default:
      return "غير محددة";
  }
}

function displayRecommendation(value?: string): string {
  const recommendation = (value || "").trim();
  const translations: Record<string, string> = {
    "Review the account list, source host, and authentication context. Correlate with VPN, firewall, and endpoint logs when available.":
      "راجعي الحسابات المستهدفة والجهاز المصدر وسياق المصادقة، ثم قارني النتائج مع سجلات VPN والجدار الناري والأجهزة الطرفية إن توفرت.",
    "Verify the activity with the account owner. Review logon type, workstation, authentication package, and nearby events. Preserve evidence for analyst review.":
      "تحققي من النشاط مع صاحب الحساب، وراجعي نوع تسجيل الدخول ومحطة العمل وحزمة المصادقة والأحداث القريبة. احتفظي بالأدلة لمراجعة المحلل.",
    "Verify whether the source and affected accounts are expected. Review nearby successful logons and Windows failure-status details before blocking or disabling anything.":
      "تحققي مما إذا كان المصدر والحسابات المتأثرة متوقعة، وراجعي عمليات الدخول الناجحة القريبة وتفاصيل فشل Windows قبل حظر أي شيء أو تعطيله.",
    "Confirm which account was locked out. Check related failed-logon events and the caller computer. Do not unlock the account until the cause is understood.":
      "حددي الحساب الذي تم قفله، وراجعي محاولات الدخول الفاشلة والجهاز المتسبب في القفل. لا تفتحي الحساب قبل فهم السبب.",
  };
  return translations[recommendation] || recommendation || "لا توجد توصية مسجلة";
}


function IpSearchPage() {

  const [ipAddress, setIpAddress] = useState("");

  const [result, setResult] = useState<IpAnalysisResult | null>(null);

  const [searching, setSearching] = useState(false);

  const [error, setError] = useState("");

  const analyzeIp = async (event: FormEvent<HTMLFormElement>) => {

    event.preventDefault();

    const query = ipAddress.trim();

    if (!query) {

      setError("أدخلي عنوان IP أولًا.");

      return;

    }

    let token: string;

    try {

      const user = auth.currentUser;

      if (!user) {

        setError("انتهت جلسة الدخول. سجّلي الدخول مرة أخرى.");

        return;

      }

      token = await user.getIdToken();

    } catch (authError) {

      console.error("Unable to get Firebase token:", authError);

      setError("تعذر التحقق من جلسة الدخول. سجّلي الدخول مرة أخرى.");

      return;

    }

    setSearching(true);

    setError("");

    setResult(null);

    try {

      const ipAnalysisUrl = `${API_BASE}/api/ip-analysis/${encodeURIComponent(query)}`;
      const requestIpAnalysis = (accessToken: string) =>
        fetch(ipAnalysisUrl, {
          method: "GET",
          headers: {
            Authorization: `Bearer ${accessToken}`,
            Accept: "application/json",
          },
        });

      let response = await requestIpAnalysis(token);

      // A Firebase ID token can expire while the dashboard remains open.
      // Refresh it once and retry rather than immediately showing an auth error.
      if (response.status === 401 && auth.currentUser) {
        token = await auth.currentUser.getIdToken(true);
        response = await requestIpAnalysis(token);
      }

      const body = await response.json().catch(() => null);

      if (response.status === 401 || response.status === 403) {

        throw new Error("رفض الخادم تسجيل الدخول بعد تحديث رمز Firebase. تحققي من سجل الخادم إذا استمر الخطأ.");

      }

      if (!response.ok) {

        const detail =

          body && typeof body.detail === "string"

            ? body.detail

            : `فشل التحليل (HTTP ${response.status}).`;

        throw new Error(detail);

      }

      setResult(normalizeIpAnalysisResult(body));

    } catch (requestError) {

      console.error("IP analysis error:", requestError);

      setError(

        requestError instanceof Error

          ? requestError.message

          : "تعذر الاتصال بخادم التحليل.",

      );

    } finally {

      setSearching(false);

    }

  };

  const riskClass = (risk?: string) => {

    switch ((risk || "Unknown").toLowerCase()) {

      case "high":

      case "critical":

        return "ip-risk ip-risk-high";

      case "medium":

        return "ip-risk ip-risk-medium";

      case "low":

        return "ip-risk ip-risk-low";

      default:

        return "ip-risk ip-risk-unknown";

    }

  };

  return (

    <section className="ip-page" aria-labelledby="ip-page-title">

      <div className="ip-page-heading">

        <div>

          <p className="ip-eyebrow">NEXUSAI SECURITY TOOLS</p>

          <h1 id="ip-page-title">تحليل عنوان IP</h1>

          <p>ابحثي في سجلات الأمان المتاحة عن الأحداث المرتبطة بعنوان محدد.</p>

        </div>

      </div>

      <form className="ip-search-form" onSubmit={analyzeIp}>

        <label htmlFor="ip-address-input">عنوان IP</label>

        <div className="ip-search-row">

          <input

            id="ip-address-input"

            value={ipAddress}

            onChange={(event) => setIpAddress(event.target.value)}

            placeholder="مثال: 192.168.1.99"

            autoComplete="off"

            spellCheck={false}

            inputMode="text"

            aria-describedby="ip-search-help"

          />

          <button type="submit" disabled={searching}>

            {searching ? "جارٍ التحليل..." : "تحليل العنوان"}

          </button>

        </div>

        <p id="ip-search-help" className="ip-help">

          يتم البحث في ملف السجلات الذي يقرأه الخادم، ولا يجري فحصًا مباشرًا للشبكات الخارجية.

        </p>

      </form>

      {error && (

        <div className="ip-error" role="alert">

          {error}

        </div>

      )}

      {searching && (

        <div className="ip-status" role="status" aria-live="polite">

          جارٍ البحث في السجلات الأمنية...

        </div>

      )}

      {result && (

        <div className="ip-results" aria-live="polite">

          <div className="ip-result-heading">

            <div>

              <p className="ip-eyebrow">RESULTS FOR</p>

              <h2>{result.ip_address}</h2>

            </div>

            <span className={riskClass(result.risk_level)}>

              {result.risk_level === "High"

                ? "خطورة مرتفعة"

                : result.risk_level === "Medium"

                  ? "خطورة متوسطة"

                  : result.risk_level === "Low"

                    ? "خطورة منخفضة"

                    : "غير محددة"}

            </span>

          </div>

          {!result.found && (

            <div className="ip-empty">

              <h3>لم يُعثر على سجلات مطابقة</h3>

              <p>{result.message}</p>

              <p>هذا لا يعني أن العنوان آمن؛ يعني فقط أنه غير موجود في السجلات المتاحة.</p>

            </div>

          )}

          <div className="ip-metrics">

            <article className="ip-metric">

              <span>الأحداث المطابقة</span>

              <strong>{result.total_events}</strong>

            </article>

            <article className="ip-metric">

              <span>تنبيهات مرتبطة بالدخول الفاشل</span>

              <strong>{result.failed_login_events}</strong>

            </article>

            <article className="ip-metric">

              <span>المحاولات المسجلة</span>

              <strong>

                {result.failed_attempts_recorded === null

                  ? "غير متاح"

                  : result.failed_attempts_recorded}

              </strong>

            </article>

            <article className="ip-metric">

              <span>الحسابات المرتبطة</span>

              <strong>{result.usernames.length}</strong>

            </article>

          </div>

          {result.usernames.length > 0 && (

            <section className="ip-panel">

              <h3>الحسابات المرتبطة</h3>

              <div
                className="ip-tags"
                style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: "8px" }}
              >
                {result.usernames.map((username) => (
                  <span key={username} className="ip-tag" style={{ display: "inline-flex", margin: 0 }}>
                    {username}
                  </span>
                ))}
              </div>

            </section>

          )}

          {result.events.length > 0 && (

            <section className="ip-panel">

              <h3>سجل الأحداث</h3>

              <div className="ip-table-wrap">

                <table className="ip-table">

                  <thead>

                    <tr>

                      <th>التوقيت</th>

                      <th>المستخدم</th>

                      <th>نوع الحدث</th>

                      <th>الخطورة</th>

                      <th>التوصية</th>

                    </tr>

                  </thead>

                  <tbody>

                    {result.events.map((item, index) => (

                      <tr key={`${item.timestamp || "time"}-${item.event_type || "event"}-${index}`}>

                        <td>{formatTimestamp(item.timestamp)}</td>

                        <td>{item.username || "غير معروف"}</td>

                        <td dir="auto">{displayEventTitle(item.event_type)}</td>

                        <td>
                          <span className={riskClass(item.risk_level)}>
                            {displayRisk(item.risk_level)}
                          </span>
                        </td>

                        <td dir="auto">{displayRecommendation(item.recommendation)}</td>

                      </tr>

                    ))}

                  </tbody>

                </table>

              </div>

            </section>

          )}

          <section className="ip-panel ip-notes">

            <h3>حدود التحليل</h3>

            <p>{result.risk_note}</p>

            <p>{result.attempts_note}</p>

            <p>مصدر البيانات: {result.analysis_basis}</p>

          </section>

        </div>

      )}

    </section>

  );

}


type AIAnomaly = {
  timestamp?: string;
  username?: string;
  source_ip?: string;
  event_type?: string;
  failed_attempts?: number;
  risk_level?: string;
  is_anomaly?: boolean;
  anomaly_score?: number;
  reasons?: string[];
};

type AIAnomalyResponse = {
  model: string;
  sample_size: number;
  live_windows_events: number;
  scored_records: number;
  anomalies_flagged: number;
  score_note: string;
  data_note: string;
  monitoring_note: string;
  results: AIAnomaly[];
};

function AIAnomalyPanel() {
  const [result, setResult] = useState<AIAnomalyResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const runAnalysis = useCallback(async () => {
    const user = auth.currentUser;
    if (!user) {
      setError("سجّلي الدخول أولًا لتشغيل تحليل الشذوذ.");
      return;
    }

    setBusy(true);
    setError("");
    try {
      let token = await user.getIdToken();
      const call = (accessToken: string) => fetch(`${API_BASE}/api/ai/anomalies`, {
        method: "GET",
        headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json" },
      });
      let response = await call(token);
      if (response.status === 401 && auth.currentUser) {
        token = await auth.currentUser.getIdToken(true);
        response = await call(token);
      }
      const body = await response.json().catch(() => null);
      if (!response.ok) {
        throw new Error(
          typeof body?.detail === "string"
            ? body.detail
            : `تعذر تشغيل تحليل الشذوذ (HTTP ${response.status}).`,
        );
      }
      setResult(body as AIAnomalyResponse);
    } catch (e) {
      setError(e instanceof Error ? e.message : "تعذر الاتصال بخدمة تحليل الشذوذ.");
    } finally {
      setBusy(false);
    }
  }, []);

  useEffect(() => {
    void runAnalysis();
  }, [runAnalysis]);

  const cardStyle = {
    padding: "18px",
    borderRadius: "14px",
    border: "1px solid var(--border, #263248)",
    background: "var(--card, #101827)",
    color: "var(--text, #e8eef8)",
  } as const;

  return (
    <section aria-labelledby="ai-anomaly-title" style={{ display: "grid", gap: "14px", marginTop: "24px" }}>
      <div style={cardStyle}>
        <div style={{ display: "flex", alignItems: "start", justifyContent: "space-between", gap: "16px", flexWrap: "wrap" }}>
          <div>
            <p style={{ margin: "0 0 6px", color: "#55e6a5", fontWeight: 700, fontSize: "12px", letterSpacing: ".08em" }}>MACHINE LEARNING</p>
            <h2 id="ai-anomaly-title" style={{ margin: "0 0 8px", fontSize: "21px" }}>كشف الأنشطة غير المعتادة</h2>
            <p style={{ margin: 0, color: "var(--muted, #aab5c7)", lineHeight: 1.7 }}>
              يستخدم النموذج غير الخاضع للإشراف Isolation Forest لترتيب السجلات حسب الشذوذ النسبي.
            </p>
          </div>
          <button type="button" className="secondary-button" onClick={() => void runAnalysis()} disabled={busy}>
            {busy ? "جارٍ التحليل..." : "إعادة تحليل السجلات"}
          </button>
        </div>
        {error && <div role="alert" style={{ marginTop: "14px", padding: "12px", borderRadius: "10px", background: "rgba(220, 70, 70, .12)", color: "#ffb4b4" }}>{error}</div>}
        {result && (
          <>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(145px, 1fr))", gap: "10px", marginTop: "18px" }}>
              {[
                ["النموذج", result.model],
                ["السجلات المحللة", String(result.sample_size)],
                ["سجلات اعتبرها النموذج شاذة", String(result.anomalies_flagged)],
                ["أحداث Windows المستلمة", String(result.live_windows_events)],
              ].map(([label, value]) => (
                <div key={label} style={{ padding: "12px", borderRadius: "10px", background: "rgba(127, 146, 170, .10)" }}>
                  <div style={{ color: "var(--muted, #aab5c7)", fontSize: "12px", marginBottom: "6px" }}>{label}</div>
                  <strong style={{ fontSize: "18px", overflowWrap: "anywhere" }}>{value}</strong>
                </div>
              ))}
            </div>
            <div style={{ overflowX: "auto", marginTop: "16px" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", minWidth: "620px" }}>
                <thead><tr>{["التوقيت", "المستخدم", "عنوان IP", "الدرجة النسبية", "نتيجة النموذج", "مؤشرات المراجعة"].map((h) => <th key={h} style={{ padding: "10px", textAlign: "right", borderBottom: "1px solid var(--border, #263248)" }}>{h}</th>)}</tr></thead>
                <tbody>
                  {result.results.slice(0, 8).map((item, index) => (
                    <tr key={`${item.timestamp}-${item.source_ip}-${index}`}>
                      <td style={{ padding: "10px", borderBottom: "1px solid var(--border, #263248)" }}>{formatTimestamp(item.timestamp)}</td>
                      <td style={{ padding: "10px", borderBottom: "1px solid var(--border, #263248)" }}>{item.username || "غير معروف"}</td>
                      <td dir="ltr" style={{ padding: "10px", borderBottom: "1px solid var(--border, #263248)" }}>{item.source_ip || "N/A"}</td>
                      <td style={{ padding: "10px", borderBottom: "1px solid var(--border, #263248)" }}>{item.anomaly_score ?? 0}/100</td>
                      <td style={{ padding: "10px", borderBottom: "1px solid var(--border, #263248)", color: item.is_anomaly ? "#ffbd69" : "#91dfbd", fontWeight: 700 }}>{item.is_anomaly ? "غير معتاد للمراجعة" : "لم يصنفه النموذج كشذوذ"}</td>
                      <td style={{ padding: "10px", borderBottom: "1px solid var(--border, #263248)", lineHeight: 1.6 }}>{(item.reasons || []).join(" ")}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p style={{ margin: "12px 0 0", color: "var(--muted, #aab5c7)", fontSize: "12px", lineHeight: 1.8 }}>{result.score_note} {result.data_note}</p>
            <p style={{ margin: "4px 0 0", color: "var(--muted, #aab5c7)", fontSize: "12px", lineHeight: 1.8 }}>{result.monitoring_note}</p>
          </>
        )}
      </div>
    </section>
  );
}

export default function App() {

  const [userChecked, setUserChecked] = useState(false);

  const [loggedIn, setLoggedIn] = useState(false);

  const [authPage, setAuthPage] = useState<"login" | "register">("login");

  const [page, setPage] = useState<PageId | "ip-search">("overview");

  const [summary, setSummary] = useState<Summary | null>(null);

  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);

  const [loading, setLoading] = useState(false);

  const [error, setError] = useState("");

  useEffect(() => {

    const unsubscribe = onAuthStateChanged(

      auth,

      (user) => {

        setLoggedIn(Boolean(user));

        setUserChecked(true);

      },

      (authError) => {

        console.error("Firebase authentication error:", authError);

        setLoggedIn(false);

        setUserChecked(true);

      },

    );

    return unsubscribe;

  }, []);

  const loadData = useCallback(async () => {

    const user = auth.currentUser;

    if (!user) {

      setSummary(null);

      setAlerts([]);

      setError("انتهت جلسة تسجيل الدخول. سجّلي الدخول مرة أخرى.");

      return;

    }

    setLoading(true);

    setError("");

    try {

      const requestDashboardData = (accessToken: string) => {
        const headers = { Authorization: `Bearer ${accessToken}` };
        return Promise.all([
          fetch(`${API_BASE}/api/summary`, { headers }),
          fetch(`${API_BASE}/api/alerts`, { headers }),
        ]);
      };

      let token = await user.getIdToken();
      let [summaryResponse, alertsResponse] = await requestDashboardData(token);

      // Refresh only after a 401, not on every periodic dashboard refresh.
      if (summaryResponse.status === 401 || alertsResponse.status === 401) {
        token = await user.getIdToken(true);
        [summaryResponse, alertsResponse] = await requestDashboardData(token);
      }

      if (summaryResponse.status === 401 || alertsResponse.status === 401) {

        throw new Error(

          "رفض الخادم رمز المصادقة حتى بعد تحديثه. راجعي سجل طرفية Backend لمعرفة سبب رفض Firebase.",

        );

      }

      if (!summaryResponse.ok || !alertsResponse.ok) {

        throw new Error(

          `تعذر تحميل البيانات. حالة الملخص: ${summaryResponse.status}، حالة التنبيهات: ${alertsResponse.status}.`,

        );

      }

      const summaryData: Summary = await summaryResponse.json();

      const alertsData: SecurityAlert[] = await alertsResponse.json();

      setSummary(summaryData);

      setAlerts(alertsData);

    } catch (err) {

      console.error("Data loading error:", err);

    setError(

        err instanceof Error ? err.message : "تعذر تحميل البيانات من الخادم.",

      );

    } finally {

      setLoading(false);

    }

  }, []);

  useEffect(() => {

    if (!loggedIn) {

      setSummary(null);

      setAlerts([]);

      return;

    }

    void loadData();

  const timer = window.setInterval(() => {

      void loadData();

    }, 30000);

    return () => window.clearInterval(timer);

  }, [loggedIn, loadData]);

  async function handleLogout() {

    try {

      await signOut(auth);

      setPage("overview");

      setAuthPage("login");

      setSummary(null);

      setAlerts([]);

      setError("");

    } catch (err) {

      console.error("Logout error:", err);

      setError("تعذر تسجيل الخروج. حاولي مرة أخرى.");

    }

  }

  function renderPage() {

    if (page === "ip-search") {

      return <IpSearchPage />;

    }

    switch (page) {

      case "analysis":

      return (
        <>
          <SecurityAnalysis alerts={alerts} loading={loading} />
          <AIAnomalyPanel />
        </>
      );

      case "alerts":

      return <Alerts alerts={alerts} loading={loading} />;

      case "recommendations":

      return <Recommendations alerts={alerts} loading={loading} />;

      case "logs":

      return <LogAnalysis alerts={alerts} loading={loading} />;

      case "status":

      return <SystemStatus apiBase={API_BASE} />;

      default:

        return (

          <Overview summary={summary} alerts={alerts} loading={loading} />

        );

    }

  }

  if (!userChecked) {

    return (

      <main

        dir="rtl"

        style={{

          minHeight: "100vh",

          display: "grid",

          placeItems: "center",

          background: "#080d18",

          color: "#55e6a5",

          fontFamily: "Tahoma, Arial, sans-serif",

        }}

      >

        جارٍ التحقق من تسجيل الدخول...

      </main>

    );

  }

  if (!loggedIn) {

    if (authPage === "register") {

      return (

        <Register

          onRegister={() => setLoggedIn(true)}

          onGoToLogin={() => setAuthPage("login")}

        />

      );

    }

    return (

      <Login

        onLogin={() => setLoggedIn(true)}

        onGoToRegister={() => setAuthPage("register")}

      />

    );

  }

  return (

    <div className="app-shell" dir="rtl">

      <aside className="sidebar">

        <div className="brand">

          <div className="brand-mark">N</div>

          <div>

            <strong>NexusAI</strong>

            <span>منصة البنية التحتية الذكية</span>

          </div>

        </div>

        <p className="nav-caption">القائمة الرئيسية</p>

        <nav className="navigation">

          {navigation.map((item) => (

            <button

              type="button"

              key={item.id}

              className={`nav-link ${page === item.id ? "active" : ""}`}

              onClick={() => setPage(item.id)}

            >

              {item.label}

            </button>

          ))}

        </nav>

        <button

          type="button"

          className="secondary-button"

          onClick={() => void loadData()}

          disabled={loading}

        >

          {loading ? "جارٍ التحديث..." : "تحديث البيانات"}

        </button>

        <button

          type="button"

          className="secondary-button"

          onClick={() => void handleLogout()}

        >

          تسجيل الخروج

        </button>

      </aside>

      <main className="main-area">

        {error && (

          <div className="error-banner" role="alert">

            {error}

          </div>

        )}

        {renderPage()}

        <footer className="app-footer">

          <strong>NexusAI</strong>

          <span>لوحة إدارة وتحليل البنية التحتية</span>

        </footer>

      </main>

    </div>

  );

}
