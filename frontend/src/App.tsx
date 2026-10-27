

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
  import.meta.env.VITE_API_URL || "http://127.0.0.1:8000"
).replace(/\/+$/, "");

const COLLECTOR_BASE = (
  import.meta.env.VITE_COLLECTOR_URL || "http://127.0.0.1:8766"
).replace(/\/+$/, "");

// Local testing only. Do not use a public, production collector token in frontend code.
const COLLECTOR_TOKEN =
  import.meta.env.VITE_COLLECTOR_TOKEN || "SmarTechLocalTest2026";

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

type CollectorResponse = {
  project?: string;
  count?: number;
  events?: Record<string, unknown>[];
};

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function firstPresent(
  row: Record<string, unknown>,
  ...keys: string[]
): unknown {
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
  if (value === null || value === undefined || String(value).trim() === "") {
    return null;
  }
  const parsed = Number(value);
  return Number.isFinite(parsed) && Number.isInteger(parsed) && parsed >= 0
    ? parsed
    : null;
}

function splitAccountNames(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.flatMap((item) => splitAccountNames(item));
  }

  const raw = textValue(value);
  if (
    !raw ||
    /^حسابات متعددة$/i.test(raw) ||
    /\b\d+\s+distinct\s+accounts?\b/i.test(raw)
  ) {
    return [];
  }

  return raw
    .split(/[,;،]+/)
    .map((item) => item.trim())
    .filter((item) => {
      if (!item) return false;
      if (
        /^(unknown|n\/a|none|غير معروف|غير محدد|حسابات متعددة)$/i.test(item)
      ) {
        return false;
      }
      return !/\bdistinct\s+accounts?\b/i.test(item);
    });
}

function normalizeIpEvent(value: unknown): IpEvent {
  const row = asRecord(value);

  const timestamp = textValue(
    firstPresent(
      row,
      "timestamp",
      "Timestamp",
      "start_time",
      "startTime",
      "StartTime",
      "first_seen",
      "first_seen_utc",
      "time",
      "TimeCreated",
      "start",
    ),
  );

  const rawUsername = firstPresent(
    row,
    "username",
    "user",
    "User",
    "TargetUserName",
    "account",
    "Accounts",
  );

  const accounts = splitAccountNames(rawUsername);
  const usernameText = textValue(rawUsername);
  const username = /\bdistinct\s+accounts?\b/i.test(usernameText)
    ? "حسابات متعددة"
    : accounts.length > 0
      ? accounts.join("، ")
      : usernameText;

  const eventId = textValue(
    firstPresent(row, "EventID", "event_id", "EventIDs", "event_ids"),
  );

  const eventType =
    textValue(
      firstPresent(
        row,
        "event_type",
        "title",
        "Title",
        "alert_title",
        "event",
        "Event Type",
        "RuleName",
        "RuleID",
        "EventID",
        "event_id",
        "action",
      ),
    ) || "حدث غير معروف";

  const rawRisk = textValue(
    firstPresent(
      row,
      "risk_level",
      "risk",
      "Risk Level",
      "severity",
      "Severity",
    ),
  );

  const normalizedRisk = /^(critical|high|عالي|عالية|مرتفع|مرتفعة)$/i.test(
    rawRisk,
  )
    ? "High"
    : /^(medium|moderate|متوسط|متوسطة)$/i.test(rawRisk)
      ? "Medium"
      : /^(low|منخفض|منخفضة)$/i.test(rawRisk)
        ? "Low"
        : rawRisk || "Unknown";

  const count = parseCount(
    firstPresent(
      row,
      "failed_attempts",
      "failed_attempt_count",
      "Count",
      "count",
      "Failed Attempts",
    ),
  );

  const successEvent =
    /successful\s+(logon|login)|نجاح\s+تسجيل\s+الدخول/i.test(eventType) ||
    eventId === "4624";

  const inferredFailed =
    !successEvent &&
    (/failed\s+(logon|login)|repeated\s+failed|فشل\s+تسجيل\s+الدخول/i.test(
      eventType,
    ) ||
      eventId === "4625");

  return {
    ...row,
    timestamp: timestamp || "",
    username: username || "غير معروف",
    source_ip: textValue(
      firstPresent(
        row,
        "source_ip",
        "SourceIP",
        "ip_address",
        "IpAddress",
        "ip",
        "Source IP",
      ),
    ),
    event_type: eventType,
    risk_level: normalizedRisk,
    recommendation: textValue(
      firstPresent(
        row,
        "recommendation",
        "Recommendation",
        "action_recommendation",
      ),
    ),
    failed_attempts: count === null ? undefined : count,
    is_failed_login:
      typeof row.is_failed_login === "boolean"
        ? row.is_failed_login
        : inferredFailed,
  };
}

function normalizeIpAnalysisResult(value: unknown): IpAnalysisResult {
  const body = asRecord(value);
  const events = Array.isArray(body.events)
    ? body.events.map(normalizeIpEvent)
    : [];

  const usernames = [
    ...new Set([
      ...splitAccountNames(body.usernames),
      ...events.flatMap((item) => splitAccountNames(item.username)),
    ]),
  ];

  const totalEvents = parseCount(body.total_events) ?? events.length;
  const failedEvents =
    parseCount(body.failed_login_events) ??
    events.filter((item) => item.is_failed_login).length;

  let attempts = parseCount(body.failed_attempts_recorded);
  let attemptsNote = textValue(body.attempts_note);

  if (attempts === null) {
    const knownCounts = events
      .filter((item) => item.is_failed_login)
      .map((item) => parseCount(item.failed_attempts))
      .filter((item): item is number => item !== null);

    if (knownCounts.length > 0) {
      attempts = Math.max(...knownCounts);
      attemptsNote =
        "هذا أكبر عدد مسجل في تنبيه واحد مرتبط بمحاولات الدخول الفاشلة؛ لم نجمع التنبيهات المتداخلة لتجنب العد المزدوج.";
    }
  }

  const riskRank: Record<string, number> = {
    Unknown: 0,
    Low: 1,
    Medium: 2,
    High: 3,
    Critical: 3,
  };

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
    analysis_basis:
      textValue(body.analysis_basis) || "سجلات الأمان المتاحة للخادم فقط",
    risk_note:
      textValue(body.risk_note) ||
      "مستوى الخطورة مؤشر للفرز الأولي وليس دليلًا قاطعًا على وقوع هجوم.",
    attempts_note:
      attemptsNote ||
      "قد تشير عدة تنبيهات إلى الأحداث نفسها؛ لا يُعد عدد التنبيهات بالضرورة عدد محاولات فريدة.",
    message:
      textValue(body.message) ||
      (events.length
        ? "عُثر على أحداث مطابقة في السجلات المتاحة."
        : "لم يُعثر على أحداث مطابقة في السجلات المتاحة."),
  };
}

function formatTimestamp(value?: string): string {
  const timestamp = (value || "").trim();
  if (!timestamp || /^(n\/a|na|unknown)$/i.test(timestamp)) {
    return "غير متاح";
  }

  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) return timestamp;

  return new Intl.DateTimeFormat("ar-SA-u-ca-gregory", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

function displayEventTitle(value?: string): string {
  const title = (value || "").trim();
  const translations: Record<string, string> = {
    "Multiple accounts targeted from one IP":
      "استهداف عدة حسابات من عنوان IP واحد",
    "Successful logon after repeated failures":
      "تسجيل دخول ناجح بعد محاولات فاشلة متكررة",
    "Repeated failed logons from one IP":
      "تكرار محاولات تسجيل الدخول الفاشلة من عنوان IP واحد",
    "Windows account lockout observed": "رصد قفل حساب Windows",
    "4624": "تسجيل دخول ناجح إلى Windows",
    "4625": "محاولة تسجيل دخول فاشلة إلى Windows",
    "4740": "قفل حساب Windows",
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
  return (
    translations[recommendation] || recommendation || "لا توجد توصية مسجلة"
  );
}

async function readResponseBody(response: Response): Promise<unknown> {
  return response.json().catch(() => null);
}

function getErrorMessage(body: unknown, fallback: string): string {
  const record = asRecord(body);
  return typeof record.detail === "string" ? record.detail : fallback;
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

    const user = auth.currentUser;
    if (!user) {
      setError("انتهت جلسة الدخول. سجّلي الدخول مرة أخرى.");
      return;
    }

    setSearching(true);
    setError("");
    setResult(null);

    try {
      let token = await user.getIdToken();
      const url = `${API_BASE}/api/ip-analysis/${encodeURIComponent(query)}`;

      const request = (accessToken: string) =>
        fetch(url, {
          method: "GET",
          headers: {
            Authorization: `Bearer ${accessToken}`,
            Accept: "application/json",
          },
        });

      let response = await request(token);

      if (response.status === 401 && auth.currentUser) {
        token = await auth.currentUser.getIdToken(true);
        response = await request(token);
      }

      const body = await readResponseBody(response);

      if (response.status === 401 || response.status === 403) {
        throw new Error(
          "رفض الخادم تسجيل الدخول بعد تحديث رمز Firebase. تحققي من سجل الخادم.",
        );
      }

      if (!response.ok) {
        throw new Error(
          getErrorMessage(body, `فشل التحليل (HTTP ${response.status}).`),
        );
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
          يتم البحث في سجلات الخادم المتاحة، ولا يجري فحصًا مباشرًا للشبكات
          الخارجية.
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
              <p>
                هذا لا يعني أن العنوان آمن؛ يعني فقط أنه غير موجود في السجلات
                المتاحة.
              </p>
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
                style={{
                  display: "flex",
                  flexWrap: "wrap",
                  alignItems: "center",
                  gap: "8px",
                }}
              >
                {result.usernames.map((username) => (
                  <span
                    key={username}
                    className="ip-tag"
                    style={{ display: "inline-flex", margin: 0 }}
                  >
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
                      <tr
                        key={`${item.timestamp || "time"}-${item.event_type || "event"}-${index}`}
                      >
                        <td>{formatTimestamp(item.timestamp)}</td>
                        <td>{item.username || "غير معروف"}</td>
                        <td dir="auto">{displayEventTitle(item.event_type)}</td>
                        <td>
                          <span className={riskClass(item.risk_level)}>
                            {displayRisk(item.risk_level)}
                          </span>
                        </td>
                        <td dir="auto">
                          {displayRecommendation(item.recommendation)}
                        </td>
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

export default function App() {
  const [userChecked, setUserChecked] = useState(false);
  const [loggedIn, setLoggedIn] = useState(false);
  const [authPage, setAuthPage] = useState<"login" | "register">("login");
  const [page, setPage] = useState<PageId | "ip-search">("overview");
  const [summary, setSummary] = useState<Summary | null>(null);
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [collectorMessage, setCollectorMessage] = useState("");

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
    setCollectorMessage("");

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

      if (summaryResponse.status === 401 || alertsResponse.status === 401) {
        token = await user.getIdToken(true);
        [summaryResponse, alertsResponse] = await requestDashboardData(token);
      }

      if (summaryResponse.status === 401 || alertsResponse.status === 401) {
        throw new Error(
          "رفض الخادم رمز المصادقة حتى بعد تحديثه. راجعي سجل Backend.",
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

  // Fetch local Windows events, then send them to the authenticated backend.
  // The backend must implement POST /api/collector/events before ingestion works.
  const collectWindowsEvents = useCallback(async () => {
    setCollectorMessage("");

    try {
      const response = await fetch(`${COLLECTOR_BASE}/events`, {
        method: "GET",
        headers: {
          Authorization: `Bearer ${COLLECTOR_TOKEN}`,
          Accept: "application/json",
        },
      });

      const body = await readResponseBody(response);

      if (!response.ok) {
        throw new Error(
          getErrorMessage(
            body,
            `تعذر قراءة سجلات Windows (HTTP ${response.status}).`,
          ),
        );
      }

      const collectorData = body as CollectorResponse;
      const events = Array.isArray(collectorData?.events)
        ? collectorData.events
        : [];

      if (events.length === 0) {
        setCollectorMessage(
          "المجمّع يعمل، لكن لم يعثر على أحداث. تحققي من إعداد ForwardedEvents في Windows.",
        );
        return;
      }

      const user = auth.currentUser;
      if (!user) {
        throw new Error("انتهت جلسة الدخول. سجّلي الدخول مرة أخرى.");
      }

      const token = await user.getIdToken();

      const ingestResponse = await fetch(`${API_BASE}/api/collector/events`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify({ events }),
      });

      const ingestBody = await readResponseBody(ingestResponse);

      if (!ingestResponse.ok) {
        throw new Error(
          getErrorMessage(
            ingestBody,
            `رفض Backend استقبال الأحداث (HTTP ${ingestResponse.status}).`,
          ),
        );
      }

      setCollectorMessage(
        `تم إرسال ${events.length} حدثًا إلى Backend. أعيدي تحميل البيانات لعرض النتائج بعد اكتمال التحليل.`,
      );
    } catch (err) {
      console.error("Windows collector error:", err);
      setCollectorMessage(
        err instanceof Error
          ? `تعذر جمع الأحداث: ${err.message}`
          : "تعذر الاتصال بمجمّع Windows.",
      );
    }
  }, []);

  const refreshAllData = useCallback(async () => {
    await collectWindowsEvents();
    await loadData();
  }, [collectWindowsEvents, loadData]);

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
      setCollectorMessage("");
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
      return <SecurityAnalysis alerts={alerts} loading={loading} />;
      case "alerts":
      return <Alerts alerts={alerts} loading={loading} />;
      case "recommendations":
    return <Recommendations alerts={alerts} loading={loading} />;
      case "logs":
      return <LogAnalysis alerts={alerts} loading={loading} />;
      case "status":
      return <SystemStatus apiBase={API_BASE} />;
      default:
        return <Overview summary={summary} alerts={alerts} loading={loading} />;
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
          onClick={() => void refreshAllData()}
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

        {collectorMessage && (
          <div className="error-banner" role="status" aria-live="polite">
            {collectorMessage}
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
