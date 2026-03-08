import { useState, useEffect, useMemo, useCallback } from "react";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell,
  AreaChart, Area, CartesianGrid, Legend, LineChart, Line
} from "recharts";

/* ─────────────────────────────────────────────
   CISA KEV LIVE ANALYSIS DASHBOARD
   Fetches live data from CISA's JSON feed
   Author: Lija Mohan
   ───────────────────────────────────────────── */

const CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

// ─── THEME ───
const T = {
  bg: "#05080f", surface: "#0c1220", card: "#111a2e", cardHover: "#152036",
  border: "#1a2744", borderLight: "#243352",
  red: "#ff3b5c", redDim: "#ff3b5c88",
  cyan: "#00e5ff", cyanDim: "#00e5ff66",
  amber: "#ffb300", amberDim: "#ffb30066",
  green: "#00e676", greenDim: "#00e67666",
  purple: "#b388ff", purpleDim: "#b388ff66",
  pink: "#ff80ab",
  text: "#e8edf5", textSec: "#8b9dc3", textMuted: "#4a5f8a",
  grid: "#152036",
};

const PALETTE = [T.red, T.cyan, T.amber, T.green, T.purple, T.pink, "#40c4ff", "#ea80fc", "#69f0ae", "#ffd740", "#448aff", "#ff6e40"];

const CWE_NAMES = {
  "CWE-20":"Input Validation","CWE-78":"OS Cmd Injection","CWE-787":"OOB Write","CWE-416":"Use After Free",
  "CWE-119":"Memory Corruption","CWE-22":"Path Traversal","CWE-502":"Deserialization","CWE-94":"Code Injection",
  "CWE-843":"Type Confusion","CWE-287":"Improper Auth","CWE-306":"Missing Auth","CWE-264":"Permissions",
  "CWE-79":"XSS","CWE-284":"Access Control","CWE-122":"Heap Overflow","CWE-77":"Command Injection",
  "CWE-89":"SQL Injection","CWE-200":"Info Disclosure","CWE-434":"Unrestricted Upload","CWE-399":"Resource Mgmt",
  "CWE-269":"Improper Privilege Mgmt","CWE-862":"Missing Authorization","CWE-863":"Incorrect Auth",
  "CWE-125":"OOB Read","CWE-190":"Integer Overflow","CWE-476":"NULL Pointer Deref","CWE-522":"Insufficient Credentials",
  "CWE-288":"Alt Auth Bypass","CWE-59":"Symlink","CWE-918":"SSRF","CWE-352":"CSRF",
};

const VULN_CATEGORIES = {
  "Memory Safety": ["CWE-787","CWE-416","CWE-122","CWE-120","CWE-119","CWE-190","CWE-125","CWE-843","CWE-476"],
  "Injection": ["CWE-79","CWE-89","CWE-78","CWE-94","CWE-77"],
  "Auth & Access": ["CWE-287","CWE-862","CWE-863","CWE-264","CWE-269","CWE-284","CWE-522","CWE-306","CWE-288"],
  "Input & Deserialization": ["CWE-20","CWE-22","CWE-502","CWE-434"],
};

const EDGE_VENDORS = ["Fortinet","SonicWall","Ivanti","Citrix","Palo Alto Networks","F5","Zyxel","Sophos","Juniper","Barracuda"];

const TABS = [
  { id: "overview", label: "Overview", icon: "◉" },
  { id: "vendors", label: "Vendors", icon: "⬡" },
  { id: "weaknesses", label: "Weaknesses", icon: "⚠" },
  { id: "ransomware", label: "Ransomware", icon: "☠" },
  { id: "edge", label: "Edge Devices", icon: "⛊" },
  { id: "timeline", label: "Timeline", icon: "◷" },
  { id: "insights", label: "Insights", icon: "✦" },
];

// ─── DATA PROCESSING ───
function processData(vulnerabilities) {
  const d = vulnerabilities;
  const total = d.length;

  // Counters
  const vendorCount = {}, productCount = {}, cweCount = {}, cveYearCount = {};
  const addedYMCount = {}, addedYearCount = {};
  const vendorRansomware = {}, vendorTotal = {};
  const prodRansomware = {};
  const cweRansomware = {};
  let ransomwareKnown = 0;
  const ages = [];
  const windows = [];
  const urgent = [];

  d.forEach(v => {
    const vendor = v.vendorProject;
    const product = v.product;
    const ransomware = v.knownRansomwareCampaignUse === "Known";

    vendorCount[vendor] = (vendorCount[vendor] || 0) + 1;
    productCount[product] = (productCount[product] || 0) + 1;
    vendorTotal[vendor] = (vendorTotal[vendor] || 0) + 1;

    if (ransomware) {
      ransomwareKnown++;
      vendorRansomware[vendor] = (vendorRansomware[vendor] || 0) + 1;
      const pk = `${vendor} ${product}`;
      prodRansomware[pk] = (prodRansomware[pk] || 0) + 1;
    }

    // CWEs
    if (v.cwes) {
      v.cwes.split(",").map(c => c.trim()).forEach(cwe => {
        if (!cwe) return;
        cweCount[cwe] = (cweCount[cwe] || 0) + 1;
        if (ransomware) cweRansomware[cwe] = (cweRansomware[cwe] || 0) + 1;
      });
    }

    // CVE Year
    const parts = v.cveID.split("-");
    if (parts.length >= 2) {
      cveYearCount[parts[1]] = (cveYearCount[parts[1]] || 0) + 1;
    }

    // Date added
    if (v.dateAdded) {
      const ym = v.dateAdded.substring(0, 7);
      const y = v.dateAdded.substring(0, 4);
      addedYMCount[ym] = (addedYMCount[ym] || 0) + 1;
      addedYearCount[y] = (addedYearCount[y] || 0) + 1;
    }

    // Age when added
    try {
      const cveYear = parseInt(parts[1]);
      const addedYear = parseInt(v.dateAdded.substring(0, 4));
      const age = Math.max(0, addedYear - cveYear);
      ages.push({ age, ...v });
    } catch(e) {}

    // Remediation window
    try {
      const added = new Date(v.dateAdded);
      const due = new Date(v.dueDate);
      const daysDiff = Math.round((due - added) / (1000*60*60*24));
      windows.push(daysDiff);
      if (daysDiff <= 3) urgent.push({ ...v, days: daysDiff });
    } catch(e) {}
  });

  // Sort helpers
  const sortedEntries = (obj, limit=15) =>
    Object.entries(obj).sort((a,b) => b[1]-a[1]).slice(0, limit);

  // Top vendors
  const topVendors = sortedEntries(vendorCount, 15).map(([name,count]) => ({ name, count }));

  // Top products
  const topProducts = sortedEntries(productCount, 12).map(([name,count]) => ({ name, count }));

  // CVE years
  const cveYears = Object.entries(cveYearCount)
    .filter(([y]) => parseInt(y) >= 2010)
    .sort((a,b) => a[0].localeCompare(b[0]))
    .map(([year,count]) => ({ year, count }));

  // Monthly (last 24)
  const allMonths = Object.keys(addedYMCount).sort();
  const last24 = allMonths.slice(-24);
  const monthlyAdditions = last24.map(m => {
    const [y,mo] = m.split("-");
    const labels = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
    return { month: `${labels[parseInt(mo)-1]} ${y.slice(2)}`, count: addedYMCount[m] };
  });

  // Added per year
  const addedPerYear = Object.entries(addedYearCount).sort((a,b)=>a[0].localeCompare(b[0])).map(([year,count])=>({year:parseInt(year),count}));

  // Top CWEs
  const topCWEs = sortedEntries(cweCount, 15).map(([cwe,count]) => ({
    cwe, name: CWE_NAMES[cwe] || cwe, count
  }));

  // Vuln categories
  const vulnCategories = Object.entries(VULN_CATEGORIES).map(([category, cwes]) => ({
    category, count: cwes.reduce((s, c) => s + (cweCount[c]||0), 0)
  }));

  // Ransomware intensity
  const ransomwareIntensity = Object.entries(vendorTotal)
    .filter(([,t]) => t >= 5)
    .map(([vendor, t]) => ({
      vendor, known: vendorRansomware[vendor]||0, total: t,
      pct: Math.round(((vendorRansomware[vendor]||0)/t)*100)
    }))
    .sort((a,b) => b.pct - a.pct)
    .slice(0, 12);

  // Ransomware products
  const ransomwareProducts = sortedEntries(prodRansomware, 10).map(([product,count]) => ({ product, count }));

  // Edge devices
  const edgeDevices = EDGE_VENDORS
    .filter(v => vendorTotal[v])
    .map(v => ({
      vendor: v, total: vendorTotal[v]||0,
      ransomware: vendorRansomware[v]||0,
      pct: Math.round(((vendorRansomware[v]||0)/(vendorTotal[v]||1))*100)
    }))
    .sort((a,b) => b.total - a.total);

  // Age buckets
  const ageBucketMap = {"Same year":0,"1 year":0,"2 years":0,"3 years":0,"4 years":0,"5 years":0,"6-10 yrs":0,"11+":0};
  ages.forEach(({ age }) => {
    if (age === 0) ageBucketMap["Same year"]++;
    else if (age === 1) ageBucketMap["1 year"]++;
    else if (age === 2) ageBucketMap["2 years"]++;
    else if (age === 3) ageBucketMap["3 years"]++;
    else if (age === 4) ageBucketMap["4 years"]++;
    else if (age === 5) ageBucketMap["5 years"]++;
    else if (age <= 10) ageBucketMap["6-10 yrs"]++;
    else ageBucketMap["11+"]++;
  });
  const ageBuckets = Object.entries(ageBucketMap).map(([bucket,count]) => ({ bucket, count }));

  // Remediation windows
  const winMap = {"≤14 days":0,"21 days":0,"~6 months":0,"Other":0};
  windows.forEach(w => {
    if (w <= 14) winMap["≤14 days"]++;
    else if (w <= 21) winMap["21 days"]++;
    else if (w >= 180) winMap["~6 months"]++;
    else winMap["Other"]++;
  });
  const remediationWindows = Object.entries(winMap).map(([window,count]) => ({window,count}));

  // Old CVEs recently added
  const currentYear = new Date().getFullYear();
  const oldRecent = ages
    .filter(a => {
      const addedY = parseInt(a.dateAdded?.substring(0,4));
      const cveY = parseInt(a.cveID?.split("-")[1]);
      return addedY >= currentYear - 1 && cveY <= 2015;
    })
    .sort((a,b) => b.age - a.age)
    .slice(0, 10)
    .map(a => ({
      cve: a.cveID, vendor: a.vendorProject, product: a.product, age: a.age, added: a.dateAdded
    }));

  // Ransomware CWEs
  const ransomwareCWEs = Object.entries(cweRansomware)
    .filter(([cwe]) => (cweCount[cwe]||0) >= 10)
    .map(([cwe, count]) => ({
      cwe, name: CWE_NAMES[cwe]||cwe, ransomCount: count, total: cweCount[cwe],
      pct: Math.round((count/(cweCount[cwe]||1))*100)
    }))
    .sort((a,b) => b.pct - a.pct)
    .slice(0, 10);

  // Annualized pace
  const now = new Date();
  const yearStart = new Date(now.getFullYear(), 0, 1);
  const daysSoFar = Math.max(1, Math.round((now - yearStart) / (1000*60*60*24)));
  const currentYearAdded = addedYearCount[String(now.getFullYear())] || 0;
  const annualized = Math.round(currentYearAdded * 365 / daysSoFar);

  // Most recent additions
  const recentAdds = [...d].sort((a,b) => b.dateAdded?.localeCompare(a.dateAdded)).slice(0, 8);

  return {
    total, ransomwareKnown, ransomwarePct: ((ransomwareKnown/total)*100).toFixed(1),
    uniqueVendors: Object.keys(vendorCount).length,
    uniqueProducts: Object.keys(productCount).length,
    topVendors, topProducts, cveYears, monthlyAdditions, addedPerYear,
    topCWEs, vulnCategories, ransomwareIntensity, ransomwareProducts,
    edgeDevices, ageBuckets, remediationWindows, oldRecent,
    ransomwareCWEs, annualized, currentYearAdded,
    urgentRemediations: urgent.sort((a,b) => a.days - b.days).slice(0, 9),
    recentAdds,
    peakYear: addedPerYear.reduce((max, d) => d.count > max.count ? d : max, {count:0}),
    lastUpdated: new Date().toISOString(),
    catalogDate: d.length > 0 ? d.sort((a,b) => b.dateAdded?.localeCompare(a.dateAdded))[0]?.dateAdded : "Unknown"
  };
}

// ─── COMPONENTS ───
const Spinner = () => (
  <div style={{ display:"flex", flexDirection:"column", alignItems:"center", justifyContent:"center", height:"100vh", background:T.bg }}>
    <div style={{ width:48, height:48, border:`3px solid ${T.border}`, borderTop:`3px solid ${T.cyan}`, borderRadius:"50%", animation:"spin 1s linear infinite" }} />
    <p style={{ color:T.textSec, marginTop:20, fontSize:14, fontFamily:"'DM Mono', monospace" }}>Fetching live CISA KEV data...</p>
    <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
  </div>
);

const ErrorState = ({ error, onRetry }) => (
  <div style={{ display:"flex", flexDirection:"column", alignItems:"center", justifyContent:"center", height:"100vh", background:T.bg, padding:40 }}>
    <div style={{ fontSize:48, marginBottom:16 }}>⚠</div>
    <h2 style={{ color:T.text, fontSize:18, margin:"0 0 8px" }}>Unable to fetch CISA KEV data</h2>
    <p style={{ color:T.textSec, fontSize:13, textAlign:"center", maxWidth:400, lineHeight:1.6, margin:"0 0 20px" }}>{error}</p>
    <button onClick={onRetry} style={{
      background:T.cyan, color:T.bg, border:"none", padding:"10px 24px", borderRadius:6,
      fontWeight:600, cursor:"pointer", fontSize:13
    }}>Try Again</button>
  </div>
);

const Stat = ({ label, value, sub, color=T.cyan }) => (
  <div style={{
    background:T.card, border:`1px solid ${T.border}`, borderRadius:10,
    padding:"18px 20px", borderTop:`3px solid ${color}`, minWidth:0,
    transition:"border-color 0.3s",
  }}>
    <div style={{ color:T.textMuted, fontSize:10, fontWeight:600, letterSpacing:"0.08em", textTransform:"uppercase", marginBottom:6 }}>{label}</div>
    <div style={{ color:T.text, fontSize:26, fontWeight:700, fontFamily:"'DM Mono', monospace", lineHeight:1 }}>{value}</div>
    {sub && <div style={{ color:T.textMuted, fontSize:10, marginTop:6 }}>{sub}</div>}
  </div>
);

const Section = ({ title, sub, children, style={} }) => (
  <div style={{ background:T.card, border:`1px solid ${T.border}`, borderRadius:10, padding:22, ...style }}>
    <div style={{ marginBottom:16 }}>
      <h3 style={{ color:T.text, fontSize:14, fontWeight:600, margin:0, fontFamily:"'Outfit', sans-serif" }}>{title}</h3>
      {sub && <p style={{ color:T.textMuted, fontSize:11, margin:"3px 0 0" }}>{sub}</p>}
    </div>
    {children}
  </div>
);

const Insight = ({ icon, title, body, severity="info" }) => {
  const colors = { critical:T.red, warning:T.amber, info:T.cyan, success:T.green };
  return (
    <div style={{
      background:T.card, border:`1px solid ${T.border}`, borderRadius:10,
      padding:18, borderLeft:`4px solid ${colors[severity]}`, marginBottom:10,
    }}>
      <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:6 }}>
        <span style={{ fontSize:16 }}>{icon}</span>
        <span style={{ color:T.text, fontWeight:600, fontSize:13, fontFamily:"'Outfit', sans-serif" }}>{title}</span>
      </div>
      <p style={{ color:T.textSec, fontSize:12, lineHeight:1.65, margin:0 }}>{body}</p>
    </div>
  );
};

const ChartTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{ background:"#1a2744", border:"1px solid #2a3f6a", borderRadius:8, padding:"8px 12px", boxShadow:"0 8px 32px rgba(0,0,0,0.6)" }}>
      <p style={{ color:T.text, fontSize:11, fontWeight:600, margin:0 }}>{label}</p>
      {payload.map((p, i) => (
        <p key={i} style={{ color:p.color||T.cyan, fontSize:11, margin:"3px 0 0" }}>
          {p.name}: <strong>{typeof p.value === 'number' ? p.value.toLocaleString() : p.value}</strong>
        </p>
      ))}
    </div>
  );
};

// ─── MAIN DASHBOARD ───
export default function CISAKEVDashboard() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState("overview");

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(CISA_KEV_URL);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json = await res.json();
      const processed = processData(json.vulnerabilities || []);
      setData(processed);
    } catch (e) {
      setError(e.message || "Failed to fetch data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  const D = data;

  if (loading) return <Spinner />;
  if (error || !D) return <ErrorState error={error} onRetry={fetchData} />;

  const renderOverview = () => (
    <>
      <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fit, minmax(165px, 1fr))", gap:14, marginBottom:22 }}>
        <Stat label="Total KEV Entries" value={D.total.toLocaleString()} sub="Known exploited vulnerabilities" color={T.red} />
        <Stat label="Ransomware Linked" value={D.ransomwareKnown.toLocaleString()} sub={`${D.ransomwarePct}% of all entries`} color={T.amber} />
        <Stat label="Unique Vendors" value={D.uniqueVendors} sub="Affected vendors" color={T.cyan} />
        <Stat label="Unique Products" value={D.uniqueProducts} sub="Distinct products" color={T.green} />
        <Stat label={`${new Date().getFullYear()} Pace`} value={`~${D.annualized}/yr`} sub={`${D.currentYearAdded} so far this year`} color={T.purple} />
        <Stat label="Peak Year Added" value={D.peakYear.count} sub={`${D.peakYear.year} — catalog launch surge`} color={T.pink} />
      </div>
      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:16, marginBottom:16 }}>
        <Section title="Monthly Additions Trend" sub="CVEs added per month (last 24 months)">
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={D.monthlyAdditions}>
              <defs><linearGradient id="ag" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor={T.cyan} stopOpacity={0.25}/><stop offset="95%" stopColor={T.cyan} stopOpacity={0}/></linearGradient></defs>
              <CartesianGrid strokeDasharray="3 3" stroke={T.grid} />
              <XAxis dataKey="month" tick={{fill:T.textMuted,fontSize:8}} interval={3} />
              <YAxis tick={{fill:T.textMuted,fontSize:9}} />
              <Tooltip content={<ChartTooltip />} />
              <Area type="monotone" dataKey="count" stroke={T.cyan} fill="url(#ag)" strokeWidth={2} name="CVEs Added" />
            </AreaChart>
          </ResponsiveContainer>
        </Section>
        <Section title="CVE Year Distribution" sub="Publication year of vulnerabilities in catalog">
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={D.cveYears}>
              <CartesianGrid strokeDasharray="3 3" stroke={T.grid} />
              <XAxis dataKey="year" tick={{fill:T.textMuted,fontSize:9}} />
              <YAxis tick={{fill:T.textMuted,fontSize:9}} />
              <Tooltip content={<ChartTooltip />} />
              <Bar dataKey="count" fill={T.purple} radius={[3,3,0,0]} name="CVEs" />
            </BarChart>
          </ResponsiveContainer>
        </Section>
      </div>
      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:16 }}>
        <Section title="Vulnerability Categories" sub="High-level weakness groupings">
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie data={D.vulnCategories} dataKey="count" nameKey="category" cx="50%" cy="50%" outerRadius={75} innerRadius={40} paddingAngle={3}
                label={({category,count})=>`${category}: ${count}`} style={{fontSize:10}}>
                {D.vulnCategories.map((_,i) => <Cell key={i} fill={PALETTE[i]} />)}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </Section>
        <Section title="Remediation Windows" sub="CISA-mandated patching deadlines">
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={D.remediationWindows} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke={T.grid} />
              <XAxis type="number" tick={{fill:T.textMuted,fontSize:9}} />
              <YAxis type="category" dataKey="window" tick={{fill:T.textSec,fontSize:10}} width={75} />
              <Tooltip content={<ChartTooltip />} />
              <Bar dataKey="count" fill={T.amber} radius={[0,3,3,0]} name="CVEs" />
            </BarChart>
          </ResponsiveContainer>
        </Section>
      </div>
    </>
  );

  const renderVendors = () => (
    <>
      <Section title="Top 15 Vendors" sub="Vendors with the most KEV catalog entries" style={{marginBottom:16}}>
        <ResponsiveContainer width="100%" height={380}>
          <BarChart data={D.topVendors} layout="vertical" margin={{left:10}}>
            <CartesianGrid strokeDasharray="3 3" stroke={T.grid} />
            <XAxis type="number" tick={{fill:T.textMuted,fontSize:9}} />
            <YAxis type="category" dataKey="name" tick={{fill:T.textSec,fontSize:10}} width={90} />
            <Tooltip content={<ChartTooltip />} />
            <Bar dataKey="count" radius={[0,3,3,0]} name="CVEs">
              {D.topVendors.map((e,i) => <Cell key={i} fill={e.name==="Microsoft"?T.red:PALETTE[i%PALETTE.length]} />)}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </Section>
      <Section title="Top 12 Products" sub="Most frequently appearing products">
        <ResponsiveContainer width="100%" height={320}>
          <BarChart data={D.topProducts} layout="vertical" margin={{left:10}}>
            <CartesianGrid strokeDasharray="3 3" stroke={T.grid} />
            <XAxis type="number" tick={{fill:T.textMuted,fontSize:9}} />
            <YAxis type="category" dataKey="name" tick={{fill:T.textSec,fontSize:10}} width={140} />
            <Tooltip content={<ChartTooltip />} />
            <Bar dataKey="count" fill={T.cyan} radius={[0,3,3,0]} name="CVEs" />
          </BarChart>
        </ResponsiveContainer>
      </Section>
    </>
  );

  const renderWeaknesses = () => (
    <>
      <Section title="Top 15 CWE Weakness Types" sub="Most common weakness categories in exploited vulnerabilities" style={{marginBottom:16}}>
        <ResponsiveContainer width="100%" height={400}>
          <BarChart data={D.topCWEs} layout="vertical" margin={{left:20}}>
            <CartesianGrid strokeDasharray="3 3" stroke={T.grid} />
            <XAxis type="number" tick={{fill:T.textMuted,fontSize:9}} />
            <YAxis type="category" dataKey="name" tick={{fill:T.textSec,fontSize:10}} width={120} />
            <Tooltip content={<ChartTooltip />} />
            <Bar dataKey="count" radius={[0,3,3,0]} name="CVEs">
              {D.topCWEs.map((_,i) => <Cell key={i} fill={PALETTE[i%PALETTE.length]} />)}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </Section>
      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:16 }}>
        <Section title="Category Breakdown">
          <ResponsiveContainer width="100%" height={240}>
            <PieChart>
              <Pie data={D.vulnCategories} dataKey="count" nameKey="category" cx="50%" cy="50%" outerRadius={85} innerRadius={45} paddingAngle={4}>
                {D.vulnCategories.map((_,i) => <Cell key={i} fill={PALETTE[i]} />)}
              </Pie>
              <Tooltip />
              <Legend wrapperStyle={{fontSize:11,color:T.textSec}} />
            </PieChart>
          </ResponsiveContainer>
        </Section>
        <Section title="Key Takeaways">
          <div style={{color:T.textSec,fontSize:12,lineHeight:1.7}}>
            <p style={{margin:"0 0 10px"}}><span style={{color:T.red,fontWeight:600}}>Memory safety</span> dominates — OOB writes, UAFs, type confusions form the largest attack surface. This validates CISA's push for memory-safe languages.</p>
            <p style={{margin:"0 0 10px"}}><span style={{color:T.cyan,fontWeight:600}}>Input validation</span> is the #1 individual CWE — a fundamental failure exploited across all vendors.</p>
            <p style={{margin:"0 0 10px"}}><span style={{color:T.amber,fontWeight:600}}>OS command injection</span> ranks #2 — heavily concentrated in network/edge devices.</p>
            <p style={{margin:0}}><span style={{color:T.purple,fontWeight:600}}>Deserialization</span> has a disproportionate ransomware association at ~35%.</p>
          </div>
        </Section>
      </div>
    </>
  );

  const renderRansomware = () => (
    <>
      <div style={{ display:"grid", gridTemplateColumns:"repeat(3, 1fr)", gap:14, marginBottom:20 }}>
        <Stat label="Ransomware-Linked" value={D.ransomwareKnown} sub={`${D.ransomwarePct}% of catalog`} color={T.red} />
        <Stat label="Highest Intensity" value={D.ransomwareIntensity[0]?.vendor||"—"} sub={`${D.ransomwareIntensity[0]?.pct||0}% of their CVEs`} color={T.amber} />
        <Stat label="#1 Target" value={D.ransomwareProducts[0]?.product||"—"} sub={`${D.ransomwareProducts[0]?.count||0} CVEs`} color={T.purple} />
      </div>
      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:16, marginBottom:16 }}>
        <Section title="Ransomware Intensity by Vendor" sub="% of vendor's CVEs linked to ransomware (min 5 CVEs)">
          <ResponsiveContainer width="100%" height={320}>
            <BarChart data={D.ransomwareIntensity} layout="vertical" margin={{left:10}}>
              <CartesianGrid strokeDasharray="3 3" stroke={T.grid} />
              <XAxis type="number" domain={[0,100]} tickFormatter={v=>`${v}%`} tick={{fill:T.textMuted,fontSize:9}} />
              <YAxis type="category" dataKey="vendor" tick={{fill:T.textSec,fontSize:10}} width={75} />
              <Tooltip content={({active,payload})=>{
                if(!active||!payload?.length) return null;
                const d=payload[0].payload;
                return <div style={{background:"#1a2744",border:"1px solid #2a3f6a",borderRadius:8,padding:"8px 12px"}}>
                  <p style={{color:T.text,fontSize:11,fontWeight:600,margin:0}}>{d.vendor}</p>
                  <p style={{color:T.red,fontSize:11,margin:"3px 0 0"}}>{d.known}/{d.total} ({d.pct}%)</p>
                </div>;
              }} />
              <Bar dataKey="pct" radius={[0,3,3,0]} name="% Ransomware">
                {D.ransomwareIntensity.map((d,i) => <Cell key={i} fill={d.pct>=60?T.red:d.pct>=40?T.amber:"#ffd740"} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </Section>
        <Section title="Top Ransomware Products" sub="Products most targeted in ransomware campaigns">
          <ResponsiveContainer width="100%" height={320}>
            <BarChart data={D.ransomwareProducts} layout="vertical" margin={{left:10}}>
              <CartesianGrid strokeDasharray="3 3" stroke={T.grid} />
              <XAxis type="number" tick={{fill:T.textMuted,fontSize:9}} />
              <YAxis type="category" dataKey="product" tick={{fill:T.textSec,fontSize:9}} width={150} />
              <Tooltip content={<ChartTooltip />} />
              <Bar dataKey="count" fill={T.red} radius={[0,3,3,0]} name="CVEs" />
            </BarChart>
          </ResponsiveContainer>
        </Section>
      </div>
      <Section title="Ransomware-Favored CWEs" sub="Weakness types disproportionately used in ransomware attacks">
        <div style={{ display:"grid", gridTemplateColumns:"repeat(5, 1fr)", gap:8, marginTop:8 }}>
          {D.ransomwareCWEs.map((item,i) => (
            <div key={i} style={{
              background:T.surface, borderRadius:8, padding:10, textAlign:"center",
              border:`1px solid ${item.pct>=50?T.red+"44":T.border}`
            }}>
              <div style={{ color:item.pct>=50?T.red:T.amber, fontSize:18, fontWeight:700, fontFamily:"'DM Mono', monospace" }}>{item.pct}%</div>
              <div style={{ color:T.textSec, fontSize:9, marginTop:2 }}>{item.name}</div>
              <div style={{ color:T.textMuted, fontSize:8 }}>{item.cwe}</div>
            </div>
          ))}
        </div>
      </Section>
    </>
  );

  const renderEdge = () => (
    <>
      <div style={{ display:"grid", gridTemplateColumns:"repeat(3, 1fr)", gap:14, marginBottom:20 }}>
        <Stat label="Edge/Network CVEs" value={D.edgeDevices.reduce((s,d)=>s+d.total,0)} sub={`Across ${D.edgeDevices.length} perimeter vendors`} color={T.cyan} />
        <Stat label="Avg Ransomware Rate" value={`~${Math.round(D.edgeDevices.reduce((s,d)=>s+d.pct,0)/Math.max(1,D.edgeDevices.length))}%`} sub="Far above catalog average" color={T.red} />
        <Stat label="Most Targeted" value={D.edgeDevices[0]?.vendor||"—"} sub={`${D.edgeDevices[0]?.total||0} CVEs`} color={T.amber} />
      </div>
      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:16 }}>
        <Section title="Edge Device Vendors" sub="Total CVEs and ransomware links per vendor">
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={D.edgeDevices}>
              <CartesianGrid strokeDasharray="3 3" stroke={T.grid} />
              <XAxis dataKey="vendor" tick={{fill:T.textSec,fontSize:9}} />
              <YAxis tick={{fill:T.textMuted,fontSize:9}} />
              <Tooltip content={<ChartTooltip />} />
              <Bar dataKey="total" fill={T.cyan} radius={[3,3,0,0]} name="Total CVEs" />
              <Bar dataKey="ransomware" fill={T.red} radius={[3,3,0,0]} name="Ransomware" />
            </BarChart>
          </ResponsiveContainer>
        </Section>
        <Section title="Why Edge Devices Are Ransomware's Front Door">
          <div style={{color:T.textSec,fontSize:12,lineHeight:1.7}}>
            <p style={{margin:"0 0 10px"}}><span style={{color:T.red,fontWeight:600}}>SonicWall & F5</span> — Two in three CVEs linked to ransomware. Sitting at the perimeter = direct entry for attackers.</p>
            <p style={{margin:"0 0 10px"}}><span style={{color:T.amber,fontWeight:600}}>Fortinet</span> — FortiOS is a top-5 ransomware product. VPN concentrators are prized because they handle auth.</p>
            <p style={{margin:"0 0 10px"}}><span style={{color:T.cyan,fontWeight:600}}>Ivanti</span> — Rising fast. VPN/remote access products became a major 2024-2025 target.</p>
            <p style={{margin:0}}><span style={{color:T.green,fontWeight:600}}>Pattern:</span> Internet-facing, often unpatched, running privileged processes, providing network access — the perfect ransomware entry point.</p>
          </div>
        </Section>
      </div>
    </>
  );

  const renderTimeline = () => (
    <>
      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:16, marginBottom:16 }}>
        <Section title="Annual KEV Additions" sub="CVEs added per year">
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={D.addedPerYear}>
              <CartesianGrid strokeDasharray="3 3" stroke={T.grid} />
              <XAxis dataKey="year" tick={{fill:T.textSec,fontSize:10}} />
              <YAxis tick={{fill:T.textMuted,fontSize:9}} />
              <Tooltip content={<ChartTooltip />} />
              <Bar dataKey="count" fill={T.purple} radius={[3,3,0,0]} name="CVEs Added">
                {D.addedPerYear.map((d,i)=><Cell key={i} fill={d.count===D.peakYear.count?T.red:T.purple} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </Section>
        <Section title="Vulnerability Age at Addition" sub="How old are CVEs when CISA adds them?">
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={D.ageBuckets}>
              <CartesianGrid strokeDasharray="3 3" stroke={T.grid} />
              <XAxis dataKey="bucket" tick={{fill:T.textSec,fontSize:9}} />
              <YAxis tick={{fill:T.textMuted,fontSize:9}} />
              <Tooltip content={<ChartTooltip />} />
              <Bar dataKey="count" radius={[3,3,0,0]} name="CVEs">
                {D.ageBuckets.map((_,i)=><Cell key={i} fill={i<=1?T.green:i<=4?T.amber:T.red} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </Section>
      </div>
      <Section title="Ancient CVEs Still Being Exploited" sub="Vulnerabilities 10+ years old added to KEV recently" style={{marginBottom:16}}>
        <div style={{overflowX:"auto"}}>
          <table style={{width:"100%",borderCollapse:"collapse",fontSize:11}}>
            <thead><tr style={{borderBottom:`1px solid ${T.border}`}}>
              {["CVE ID","Vendor","Product","Age (yrs)","Date Added"].map(h=>
                <th key={h} style={{padding:"8px 10px",textAlign:"left",color:T.textMuted,fontWeight:500,fontSize:10}}>{h}</th>
              )}
            </tr></thead>
            <tbody>{D.oldRecent.map((r,i)=>(
              <tr key={i} style={{borderBottom:`1px solid ${T.border}22`}}>
                <td style={{padding:"8px 10px",color:T.cyan,fontFamily:"'DM Mono', monospace",fontWeight:600,fontSize:11}}>{r.cve}</td>
                <td style={{padding:"8px 10px",color:T.textSec}}>{r.vendor}</td>
                <td style={{padding:"8px 10px",color:T.textSec}}>{r.product}</td>
                <td style={{padding:"8px 10px",color:r.age>=15?T.red:T.amber,fontWeight:700,fontFamily:"monospace"}}>{r.age}</td>
                <td style={{padding:"8px 10px",color:T.textMuted}}>{r.added}</td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      </Section>
      {D.urgentRemediations.length > 0 && (
        <Section title="Emergency Remediation Orders" sub="CVEs with ≤3 day deadlines">
          <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill, minmax(240px, 1fr))",gap:8,marginTop:4}}>
            {D.urgentRemediations.map((item,i)=>(
              <div key={i} style={{background:T.surface,borderRadius:8,padding:10,borderLeft:`3px solid ${item.days===1?T.red:T.amber}`}}>
                <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
                  <span style={{color:T.cyan,fontFamily:"'DM Mono', monospace",fontSize:11,fontWeight:600}}>{item.cve || item.cveID}</span>
                  <span style={{background:item.days===1?T.red+"33":T.amber+"33",color:item.days===1?T.red:T.amber,fontSize:9,fontWeight:700,padding:"2px 6px",borderRadius:3}}>{item.days}d</span>
                </div>
                <div style={{color:T.textMuted,fontSize:10,marginTop:3}}>{item.vendor || item.vendorProject} · {item.added || item.dateAdded}</div>
              </div>
            ))}
          </div>
        </Section>
      )}
    </>
  );

  const renderInsights = () => (
    <>
      <div style={{marginBottom:16,padding:18,background:`linear-gradient(135deg, #0d1b3e 0%, ${T.bg} 100%)`,borderRadius:10,border:`1px solid ${T.purple}33`}}>
        <h3 style={{color:T.text,fontSize:15,fontWeight:700,margin:"0 0 8px",fontFamily:"'Outfit', sans-serif"}}>Executive Summary</h3>
        <p style={{color:T.textSec,fontSize:12,lineHeight:1.7,margin:0}}>
          The CISA KEV catalog contains <strong style={{color:T.text}}>{D.total.toLocaleString()}</strong> actively exploited vulnerabilities across <strong style={{color:T.text}}>{D.uniqueVendors}</strong> vendors.
          Microsoft dominates at {((D.topVendors[0]?.count/D.total)*100).toFixed(1)}%. One in five CVEs ({D.ransomwarePct}%) has confirmed ransomware exploitation.
          Edge/perimeter devices show ~2x the ransomware rate of the catalog average. Memory safety issues remain the #1 weakness category.
          CISA continues adding vulnerabilities from as far back as 2007–2008 — old CVEs never truly die.
        </p>
      </div>
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
        <div>
          <Insight icon="🔴" severity="critical" title="The Microsoft Monoculture Risk"
            body={`${D.topVendors[0]?.count} CVEs (${((D.topVendors[0]?.count/D.total)*100).toFixed(1)}%) from Microsoft — more than the next four vendors combined. Windows alone drives the bulk. Any org on Microsoft infra faces compounding vulnerability load.`} />
          <Insight icon="🏚️" severity="critical" title="The Zombie CVE Problem"
            body="CISA is still adding CVEs from 2007-2010 in 2025-2026 — vulnerabilities up to 18 years old still actively weaponized. This demolishes 'old CVEs are safe' and demands perpetual lifecycle management." />
          <Insight icon="🔓" severity="critical" title="Edge Devices: Ransomware's Front Door"
            body="Edge/network vendors show ~38% ransomware association — nearly 2x the catalog average. SonicWall, F5, and Fortinet lead intensity. Internet-facing + privileged access = perfect entry point." />
          <Insight icon="⚡" severity="warning" title="1-Day Remediation Orders Emerging"
            body={`${D.urgentRemediations.length} CVEs with ≤3 day windows, including 1-day deadlines. CISA is shifting toward near-real-time response expectations for the most critical threats.`} />
        </div>
        <div>
          <Insight icon="💾" severity="warning" title="Memory Safety: The Root Cause"
            body={`${D.vulnCategories[0]?.count} entries (~${Math.round((D.vulnCategories[0]?.count/D.total)*100)}%) are memory safety issues. This is the strongest data-driven argument for CISA's push toward memory-safe languages like Rust.`} />
          <Insight icon="🗄️" severity="warning" title="QNAP: The NAS Nightmare"
            body="82% of QNAP's KEV entries are ransomware-linked — the highest of any vendor. NAS devices store critical data, are internet-accessible, and make perfect ransomware targets." />
          <Insight icon="📈" severity="info" title={`${new Date().getFullYear()} Acceleration`}
            body={`On pace for ~${D.annualized} additions this year. After a dip in 2023-2024, the catalog is accelerating. Vendor diversity also expanding — more products, more attack surface.`} />
          <Insight icon="🔄" severity="info" title="The 21-Day Standard"
            body={`${D.remediationWindows[1]?.count || "~1000"} entries (${Math.round(((D.remediationWindows[1]?.count||1000)/D.total)*100)}%) carry a 21-day deadline. But the trend is toward shorter windows, with emergency 1-3 day deadlines becoming more common.`} />
          <Insight icon="🎯" severity="success" title="Deserialization: Ransomware's Favorite CWE"
            body="CWE-502 (Deserialization) and CWE-59 (Symlink) show the highest ransomware rates among common CWEs. These enable reliable, automatable exploitation — exactly what ransomware groups need." />
        </div>
      </div>
    </>
  );

  const tabContent = {
    overview: renderOverview, vendors: renderVendors, weaknesses: renderWeaknesses,
    ransomware: renderRansomware, edge: renderEdge, timeline: renderTimeline, insights: renderInsights
  };

  return (
    <div style={{ background:T.bg, minHeight:"100vh", color:T.text, fontFamily:"'Outfit', -apple-system, sans-serif" }}>
      <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet" />
      <style>{`
        @keyframes pulse { 0%,100% { opacity:1; } 50% { opacity:0.5; } }
        @keyframes fadeIn { from { opacity:0; transform:translateY(8px); } to { opacity:1; transform:translateY(0); } }
        .tab-btn:hover { color: ${T.cyan} !important; }
      `}</style>

      {/* Header */}
      <header style={{ padding:"24px 28px 0", borderBottom:`1px solid ${T.border}`, marginBottom:24 }}>
        <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:4 }}>
          <div style={{ display:"flex", alignItems:"center", gap:10 }}>
            <div style={{ width:8, height:8, borderRadius:"50%", background:T.red, boxShadow:`0 0 10px ${T.red}88`, animation:"pulse 2s ease-in-out infinite" }} />
            <h1 style={{ fontSize:20, fontWeight:700, margin:0, letterSpacing:"-0.02em", fontFamily:"'Outfit', sans-serif" }}>
              CISA KEV — Live Analysis
            </h1>
          </div>
          <div style={{ display:"flex", alignItems:"center", gap:14 }}>
            <span style={{ color:T.textMuted, fontSize:10, fontFamily:"'DM Mono', monospace" }}>
              {D.total.toLocaleString()} entries · Latest: {D.catalogDate}
            </span>
            <button onClick={fetchData} title="Refresh data" style={{
              background:"none", border:`1px solid ${T.border}`, borderRadius:6, color:T.textSec,
              padding:"4px 10px", cursor:"pointer", fontSize:11, fontFamily:"'DM Mono', monospace",
              transition:"all 0.2s"
            }}>↻ Refresh</button>
          </div>
        </div>
        <p style={{ color:T.textMuted, fontSize:10, margin:"2px 0 14px 18px", fontFamily:"'DM Mono', monospace" }}>
          Live data from CISA Known Exploited Vulnerabilities Catalog · Analysis by Lija Mohan
        </p>
        <nav style={{ display:"flex", gap:0, overflow:"auto" }}>
          {TABS.map(tab => (
            <button key={tab.id} className="tab-btn" onClick={() => setActiveTab(tab.id)} style={{
              background:"none", border:"none", cursor:"pointer", padding:"9px 16px",
              fontSize:12, fontWeight: activeTab===tab.id ? 600 : 400, fontFamily:"'Outfit', sans-serif",
              color: activeTab===tab.id ? T.cyan : T.textMuted,
              borderBottom: activeTab===tab.id ? `2px solid ${T.cyan}` : "2px solid transparent",
              transition:"all 0.2s", whiteSpace:"nowrap", display:"flex", alignItems:"center", gap:5,
            }}>
              <span style={{ fontSize:11 }}>{tab.icon}</span> {tab.label}
            </button>
          ))}
        </nav>
      </header>

      {/* Content */}
      <main style={{ padding:"0 28px 40px", maxWidth:1200, margin:"0 auto", animation:"fadeIn 0.3s ease" }} key={activeTab}>
        {(tabContent[activeTab] || renderOverview)()}
      </main>

      {/* Footer */}
      <footer style={{ padding:"20px 28px", borderTop:`1px solid ${T.border}`, textAlign:"center" }}>
        <p style={{ color:T.textMuted, fontSize:10, margin:0, fontFamily:"'DM Mono', monospace" }}>
          Data source: CISA Known Exploited Vulnerabilities Catalog (cisa.gov) · Built by Lija Mohan · Updates live on every page load
        </p>
      </footer>
    </div>
  );
}
