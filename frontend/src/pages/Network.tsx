
type NetworkSegment = {
name: string;
vlan: string;
subnet: string;
purpose: string;
color: string;
};

const segments: NetworkSegment[] = [
{
    name: "الموارد البشرية",
    vlan: "10",
    subnet: "192.168.10.0/24",
    purpose: "أجهزة وموظفو الموارد البشرية",
    color: "blue",
},
{
    name: "المالية",
    vlan: "20",
    subnet: "192.168.20.0/24",
    purpose: "الأنظمة المالية والمحاسبية",
    color: "medium",
},
{
    name: "تقنية المعلومات",
    vlan: "30",
    subnet: "192.168.30.0/24",
    purpose: "الإدارة التقنية والخوادم",
    color: "safe",
},
{
    name: "شبكة الضيوف",
    vlan: "40",
    subnet: "192.168.40.0/24",
    purpose: "اتصال ضيوف معزول عن الشبكة الداخلية",
    color: "danger",
},
];

export default function Network() {
return (
    <main className="page-container" dir="rtl">
    <header className="topbar">
        <div>
        <p className="eyebrow">SOC / NETWORK MANAGEMENT</p>
        <h1>إدارة الشبكة</h1>
        <p>عرض تصوري لتقسيم الشبكة إلى أقسام منفصلة حسب الوظيفة.</p>
        </div>
        <span className="connection-badge">
        <span className="status-dot" />
        تصميم تصوري
        </span>
    </header>

    <section className="dashboard-grid">
        <article className="stat-card">
        <div className="stat-top"><span>أقسام الشبكة</span><span className="stat-icon">▤</span></div>
        <strong>{segments.length}</strong>
        <small>أقسام مقترحة للتقسيم المنطقي</small>
        </article>

        <article className="stat-card">
        <div className="stat-top"><span>شبكات VLAN</span><span className="stat-icon">⌘</span></div>
        <strong>{segments.length}</strong>
        <small>معرّفات مقترحة لكل قسم</small>
        </article>

        <article className="stat-card safe">
        <div className="stat-top"><span>شبكة تقنية المعلومات</span><span className="stat-icon">✓</span></div>
        <strong>VLAN 30</strong>
        <small>شبكة مخصصة للإدارة التقنية</small>
        </article>

        <article className="stat-card danger">
        <div className="stat-top"><span>شبكة الضيوف</span><span className="stat-icon">⚠</span></div>
        <strong>VLAN 40</strong>
        <small>يجب عزلها بقواعد شبكة فعلية</small>
        </article>
    </section>

    <section className="panel">
        <div className="panel-heading">
        <div>
            <h3>تقسيم الشبكة المقترح</h3>
            <p>لكل قسم نطاق IP ومعرّف VLAN مقترح.</p>
        </div>
        <span className="panel-mark">01</span>
        </div>

        <div className="table-container">
        <table>
            <thead>
            <tr>
                <th>القسم</th>
                <th>VLAN</th>
                <th>نطاق الشبكة</th>
                <th>الغرض</th>
                <th>التصنيف</th>
            </tr>
            </thead>
            <tbody>
            {segments.map((segment) => (
                <tr key={segment.vlan}>
                <td>{segment.name}</td>
                <td><code>{segment.vlan}</code></td>
                <td><code>{segment.subnet}</code></td>
                <td>{segment.purpose}</td>
                <td>
                    <span className={`risk ${segment.color === "danger" ? "high" : segment.color === "medium" ? "medium" : "low"}`}>
                    {segment.vlan === "40" ? "ضيوف" : "داخلي"}
                    </span>
                </td>
                </tr>
            ))}
            </tbody>
        </table>
        </div>
    </section>

    <section className="analytics-grid">
        {segments.map((segment) => (
        <article className="panel network-card" key={segment.vlan}>
            <span className="network-symbol">⌘</span>
            <h3>{segment.name}</h3>
            <p>{segment.purpose}</p>
            <div className="data-table">
            <div className="data-table-row">
                <span>معرّف VLAN</span>
                <strong>{segment.vlan}</strong>
            </div>
            <div className="data-table-row">
                <span>نطاق IP</span>
                <strong>{segment.subnet}</strong>
            </div>
            </div>
        </article>
        ))}
    </section>

    <p className="chart-note">
        هذا التقسيم نموذج توضيحي فقط. لن تُنشأ شبكات VLAN فعلية ولن تُطبّق
        قيود الوصول إلا بعد إعداد أجهزة الشبكة والمبدلات والموجّهات وقواعد
        الجدار الناري المناسبة.
    </p>
    </main>
);
}
