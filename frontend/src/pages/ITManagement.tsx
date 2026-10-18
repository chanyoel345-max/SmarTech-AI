
const resources = [
{
    title: "الخوادم",
    icon: "▣",
    description: "متابعة الخوادم والخدمات المرتبطة بها.",
    status: "يتطلب الربط",
},
{
    title: "المستخدمون",
    icon: "♙",
    description: "تخطيط إدارة حسابات المستخدمين والصلاحيات.",
    status: "يتطلب الربط",
},
{
    title: "التخزين والنسخ الاحتياطي",
    icon: "▤",
    description: "متابعة سعة التخزين وخطط النسخ الاحتياطي.",
    status: "يتطلب الربط",
},
{
    title: "الأمن والوصول",
    icon: "◇",
    description: "مراجعة الصلاحيات وسياسات الوصول المقترحة.",
    status: "يتطلب الربط",
},
];

export default function ITManagement() {
return (
    <main className="page-container" dir="rtl">
    <header className="topbar">
        <div>
        <p className="eyebrow">NEXUSAI / IT INFRASTRUCTURE</p>
        <h1>إدارة البنية التحتية</h1>
        <p>مساحة موحدة لمكونات تقنية المعلومات وإدارة مواردها.</p>
        </div>
        <span className="data-label">لوحة إدارة</span>
    </header>

    <section className="dashboard-grid">
        <article className="stat-card">
        <div className="stat-top"><span>مكونات الإدارة</span><span className="stat-icon">▤</span></div>
        <strong>{resources.length}</strong>
        <small>أقسام الإدارة المعروضة</small>
        </article>

        <article className="stat-card medium">
        <div className="stat-top"><span>مصادر البيانات المرتبطة</span><span className="stat-icon">⌘</span></div>
        <strong>0</strong>
        <small>لم تُربط مصادر فعلية في هذه الصفحة</small>
        </article>

        <article className="stat-card">
        <div className="stat-top"><span>إدارة المستخدمين</span><span className="stat-icon">♙</span></div>
        <strong>—</strong>
        <small>تتطلب ربط نظام إدارة هوية</small>
        </article>

        <article className="stat-card">
        <div className="stat-top"><span>النسخ الاحتياطي</span><span className="stat-icon">▣</span></div>
        <strong>—</strong>
        <small>تتطلب ربط مصدر مراقبة التخزين</small>
        </article>
    </section>

    <section>
        <div className="section-heading">
        <div>
            <h2>موارد تقنية المعلومات</h2>
            <p>الأقسام الأساسية المقترحة لإدارة البنية التحتية.</p>
        </div>
        </div>

        <div className="analytics-grid">
        {resources.map((resource, index) => (
            <article className="panel task-card" key={resource.title}>
            <div className="panel-heading">
                <span className="stat-icon">{resource.icon}</span>
                <span className="panel-mark">
                {String(index + 1).padStart(2, "0")}
                </span>
            </div>

            <h3>{resource.title}</h3>
            <p>{resource.description}</p>

            <div className="data-table-row">
                <span>الحالة</span>
                <span className="risk medium">{resource.status}</span>
            </div>
            </article>
        ))}
        </div>
    </section>

    <section className="panel">
        <div className="panel-heading">
        <div>
            <h3>متطلبات الربط الفعلي</h3>
            <p>الخطوات اللازمة لتحويل هذه الواجهة إلى لوحة تشغيل فعلية.</p>
        </div>
        </div>

        <div className="priority-list">
        <div className="priority-item">
            <span className="priority-number">01</span>
            <div className="priority-content">
            <strong>ربط مصادر بيانات الخوادم</strong>
            <p>توفير واجهة آمنة لجمع حالة الخدمات والأجهزة.</p>
            </div>
        </div>

        <div className="priority-item">
            <span className="priority-number">02</span>
            <div className="priority-content">
            <strong>ربط نظام إدارة المستخدمين</strong>
            <p>تحديد الصلاحيات وإدارة الحسابات من خلال مصدر موثوق.</p>
            </div>
        </div>

        <div className="priority-item">
            <span className="priority-number">03</span>
            <div className="priority-content">
            <strong>إعداد الصلاحيات والتدقيق</strong>
            <p>تقييد الإجراءات الحساسة وتسجيل عمليات الإدارة.</p>
            </div>
        </div>
        </div>
    </section>

    <p className="chart-note">
        هذه الواجهة تعرض أقسامًا تنظيمية مقترحة، ولا تتحكم فعليًا بالخوادم
        أو حسابات المستخدمين أو النسخ الاحتياطية.
    </p>
    </main>
);
}
