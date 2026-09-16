import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import axios from "axios";
import {
  Shield,
  LayoutDashboard,
  Upload,
  History,
  Settings,
  Search,
  Wifi,
  FileText,
  AlertTriangle,
  CheckCircle,
  Clock,
  ChevronRight,
  MapPin,
  Link,
  Paperclip,
} from "lucide-react";
import "./style.css";
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "";
const api = axios.create({ baseURL: API_BASE_URL });
const verdicts = ["THREAT", "SPAM", "SAFE", "INCONCLUSIVE"];
function Badge({ value }) {
  const label = (value || "QUEUED").toLowerCase();
  const cls =
    label === "malicious" || label === "fail"
      ? "threat"
      : label === "suspicious" || label === "spam"
        ? "spam"
        : label === "safe" || label === "pass"
          ? "safe"
          : label;
  return <span className={"badge " + cls}>{value || "QUEUED"}</span>;
}
function App() {
  const [page, setPage] = useState("Dashboard"),
    [stats, setStats] = useState(null),
    [items, setItems] = useState([]),
    [timelineHtml, setTimelineHtml] = useState(null),
    [selected, setSelected] = useState(null),
    [running, setRunning] = useState(null),
    [file, setFile] = useState(null),
    [error, setError] = useState("");
  const load = () =>
    Promise.all([
      api.get("/api/dashboard/stats"),
      api.get("/api/analyses"),
      api.get("/api/dashboard/timeline"),
    ])
      .then(([a, b, c]) => {
        setStats(a.data);
        setItems(b.data.items);
        setTimelineHtml(c.data.html);
        setError("");
      })
      .catch((e) =>
        setError(
          e.response?.data?.detail ||
            "Backend unavailable. Start FastAPI on port 8000.",
        ),
      );
  useEffect(() => {
    load();
  }, []);
  const upload = async () => {
    if (!file || running) return;
    setError("");
    setSelected(null);
    try {
      const body = new FormData();
      body.append("file", file);
      const r = await api.post("/api/analyses", body);
      const id = r.data.analysis_id;
      setRunning({ id, stage: "queued", name: file.name });
      setFile(null);
      const poll = setInterval(async () => {
        try {
          const x = (await api.get("/api/analyses/" + id)).data;
          setRunning((cur) => (cur ? { ...cur, stage: x.stage || x.status } : cur));
          if (["completed", "failed"].includes(x.status)) {
            clearInterval(poll);
            setRunning(null);
            if (x.status === "completed") setSelected(x);
            else setError((x.errors || []).join(" · ") || "Analysis failed.");
            load();
          }
        } catch (e) {
          clearInterval(poll);
          setRunning(null);
          setError(e.response?.data?.detail || e.message);
        }
      }, 700);
    } catch (e) {
      setError(e.response?.data?.detail || e.message);
    }
  };
  const nav = [
    ["Dashboard", LayoutDashboard],
    ["Analyze Email", Upload],
    ["History", History],
    ["Settings", Settings],
  ];
  return (
    <div className="shell">
      <header>
        <div className="brand">
          <Shield /> <b>MailSentinel</b>
          <small>Email Threat Intelligence</small>
        </div>
        <div className="topsearch">
          <Search size={16} />
          <input
            placeholder="Search analysis history"
            onChange={(e) =>
              api
                .get("/api/analyses", { params: { search: e.target.value } })
                .then((r) => setItems(r.data.items))
                .catch(() => setError("Unable to search analysis history."))
            }
          />
        </div>
        <span className={error ? "offline" : "online"}>
          <Wifi size={15} />{" "}
          {error ? "Backend disconnected" : "Backend connected"}
        </span>
        <button onClick={() => setPage("Analyze Email")} className="primary">
          <Upload size={16} /> Analyze Email
        </button>
      </header>
      <div className="layout">
        <aside>
          <div className="workspace">
            <Shield size={18} />
            <span>Security Workspace</span>
          </div>
          {nav.map(([n, I]) => (
            <button
              className={page === n ? "active" : ""}
              onClick={() => setPage(n)}
              key={n}
            >
              <I size={17} />
              {n}
            </button>
          ))}
          <small className="asidefoot">
            <span className={error ? "offline-dot" : "dot"} />{" "}
            {error ? "API connection unavailable" : "API connection ready"}
          </small>
        </aside>
        <main>
          {error && <div className="error">{error}</div>}
          {running && <RunningPanel run={running} />}
          {page === "Dashboard" && (
            <Dashboard
              stats={stats}
              items={items}
              open={setSelected}
              timelineHtml={timelineHtml}
              file={file}
              setFile={setFile}
              upload={upload}
            />
          )}{" "}
          {page === "Analyze Email" && (
            <UploadPanel file={file} setFile={setFile} upload={upload} />
          )}{" "}
          {page === "History" && (
            <HistoryPanel items={items} open={setSelected} />
          )}{" "}
          {page === "Settings" && <SettingsPanel />}
          {selected && (
            <Detail item={selected} close={() => setSelected(null)} />
          )}
        </main>
        <section className="rail">
          <Chart stats={stats} />
          <div className="card activity">
            <h3>
              <Clock size={17} /> Analysis Activity
            </h3>
            <p>Single-worker local job runner</p>
            {["queued", "extracting", "analyzing", "checking", "verdict"].map(
              (x) => (
                <div className="stage" key={x}>
                  <span className="dot" />
                  {x}
                  <span>persisted</span>
                </div>
              ),
            )}
          </div>
        </section>
      </div>
    </div>
  );
}
function RunningPanel({ run }) {
  return (
    <div className="running card">
      <span className="spinner" />
      <div>
        <b>Analyzing {run.name}</b>
        <small>
          <span className={"dot " + run.stage} /> {run.stage}
        </small>
      </div>
    </div>
  );
}
function Dashboard({ stats, items, open, timelineHtml, file, setFile, upload }) {
  return (
    <>
      <h1>Email Overview</h1>
      <p className="muted">
        A clear view of the messages your workspace has examined.
      </p>
      <div className="metrics">
        {[
          ["Total Analyzed", stats?.total || 0, ""],
          ...verdicts.map((v) => [
            v[0] + v.slice(1).toLowerCase(),
            stats?.distribution?.[v] || 0,
            v,
          ]),
        ].map(([a, b, c]) => (
          <div className="metric" key={a}>
            <span>{a}</span>
            <strong>{b}</strong>
            {c && <Badge value={c} />}
          </div>
        ))}
      </div>
      <UploadPanel file={file} setFile={setFile} upload={upload} compact />
      {timelineHtml && (
        <div className="card gaugesmall">
          <h3>Inbox Threat Progression Timeline</h3>
          <iframe
            className="graphframe"
            title="Threat timeline"
            srcDoc={timelineHtml}
            sandbox="allow-scripts"
          />
        </div>
      )}
      <h2>Recent analyses</h2>
      <HistoryPanel items={items.slice(0, 5)} open={open} />
    </>
  );
}
function UploadPanel({ file, setFile, upload, compact }) {
  return (
    <div
      className="upload card"
      onDragOver={(e) => e.preventDefault()}
      onDrop={(e) => {
        e.preventDefault();
        setFile?.(e.dataTransfer.files[0]);
      }}
    >
      <Upload size={28} />
      <h2>{compact ? "Analyze a new email" : "Drop an .eml file here"}</h2>
      <p className="muted">
        Never execute attachments or visit extracted links.
      </p>
      <input
        id="picker"
        type="file"
        accept=".eml"
        hidden
        onChange={(e) => setFile?.(e.target.files[0])}
      />
      <label htmlFor="picker" className="button">
        Choose file
      </label>
      {file && (
        <>
          <span className="filename">
            {file.name} · {(file.size / 1024).toFixed(1)} KB
          </span>
          <button className="primary" onClick={upload}>
            Start analysis
          </button>
        </>
      )}
    </div>
  );
}
function HistoryPanel({ items, open }) {
  return (
    <div className="rows">
      {!items.length ? (
        <div className="empty">No analyses yet. Upload an email to begin.</div>
      ) : (
        items.map((x) => (
          <button className="row" key={x.analysis_id} onClick={() => open(x)}>
            <FileText />
            <span>
              <b>{x.extraction?.subject || x.filename}</b>
              <small>
                {x.extraction?.sender || "Pending extraction"} ·{" "}
                {new Date(x.created_at).toLocaleString()}
              </small>
            </span>
            <Badge value={x.verdict || x.status} />
            <ChevronRight size={16} />
          </button>
        ))
      )}
    </div>
  );
}
function Chart({ stats }) {
  return (
    <div className="card chart">
      <h3>Verdict Distribution</h3>
      {verdicts.map((v) => (
        <div className="bar" key={v}>
          <span className={v.toLowerCase()} />
          <label>{v}</label>
          <b>{stats?.distribution?.[v] || 0}</b>
        </div>
      ))}
    </div>
  );
}
function KV({ rows }) {
  return (
    <div className="kv">
      {rows.map(([k, v]) => (
        <span key={k}>
          {k}
          <b>{v}</b>
        </span>
      ))}
    </div>
  );
}
function Section({ icon: I, title, children }) {
  return (
    <div className="sec">
      <h3>
        {I && <I size={15} />} {title}
      </h3>
      {children}
    </div>
  );
}
function Table({ head, rows, empty }) {
  if (!rows.length) return <p className="muted">{empty || "None"}</p>;
  return (
    <div className="tablewrap">
      <table className="gtable">
        <thead>
          <tr>
            {head.map((h) => (
              <th key={h}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i}>
              {r.map((c, j) => (
                <td key={j}>{c}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
function Detail({ item, close }) {
  const ext = item.extraction;
  const provider = item.provider_results || {};
  const locations = provider.locations || [];
  const urls = provider.urls || [];
  const attachments = provider.attachments || [];
  const agent = item.agent;
  const auth = ext?.auth_headers || {};
  return (
    <div className="detail card">
      <button className="close" onClick={close}>
        Close
      </button>
      <Badge value={item.verdict || item.status} />
      <h2>{ext?.subject || item.filename}</h2>
      {item.explanation && <p className="reasoning">{item.explanation}</p>}
      {item.map_html && (
        <Section icon={MapPin} title="IP Journey Map">
          <iframe
            className="mapframe"
            title="Email journey map"
            srcDoc={item.map_html}
            style={{ width: "100%", height: "420px", border: "1px solid #ddd", borderRadius: "8px" }}
          />
        </Section>
      )}
      {ext && (
        <Section icon={FileText} title="Message">
          <KV
            rows={[
              ["Sender", ext.sender || "Unknown"],
              ["Recipient", ext.recipient || "Unknown"],
              ["Date", ext.date || "Unknown"],
              ["Return-Path", ext.return_path || "Unknown"],
              ["Message-ID", ext.message_id || "Unknown"],
              [
                "Authentication",
                `SPF ${badgeText(auth.spf_header)} · DKIM ${badgeText(auth.dkim_signature)} · DMARC ${badgeText(auth.dmarc_result)}`,
              ],
            ]}
          />
        </Section>
      )}
      {agent?.thoughts?.length > 0 && (
        <Section icon={AlertTriangle} title="Agent Analysis Trail">
          {agent.thoughts.map((t, i) => (
            <p className="agentlog" key={i}>
              {t}
            </p>
          ))}
        </Section>
      )}
      {agent?.tool_calls?.length > 0 && (
        <Section icon={Search} title="Agent Tool Executions">
          <Table
            head={["Tool", "Result"]}
            rows={agent.tool_calls.map((c) => [
              c.name,
              <code key="v">
                {typeof c.content === "string"
                  ? c.content.slice(0, 240)
                  : JSON.stringify(c.content).slice(0, 240)}
              </code>,
            ])}
            empty="The agent performed no tool lookups."
          />
        </Section>
      )}
      <Section icon={MapPin} title={`IP Hops & Geolocation (${locations.length})`}>
        {!locations.length && ext?.ip_hops?.length > 0 && (
          <p className="muted">Geolocation unavailable for extracted IPs.</p>
        )}
        {ext?.ip_hops?.length > 0 && (
          <Table
            head={["Hop", "IP", "Location", "Organization"]}
            rows={locations.map((l, i) => [
              i + 1,
              l.ip,
              [l.city, l.country].filter(Boolean).join(", ") ||
                l.error ||
                "N/A",
              l.org || "N/A",
            ])}
            empty="No public IP hops found in this email."
          />
        )}
      </Section>
      <Section icon={Link} title={`Linked URLs (${urls.length})`}>
        <Table
          head={["URL", "Status"]}
          rows={urls.map((u) => [
            u.url,
            <span key="s">
              {u.error ? (
                <span className="muted">{u.error}</span>
              ) : (
                <Badge value={u.verdict} />
              )}
            </span>,
          ])}
          empty="No links extracted from this email."
        />
      </Section>
      <Section
        icon={Paperclip}
        title={`Attachments (${(ext?.attachments || []).length})`}
      >
        <Table
          head={["File", "SHA-256", "Status"]}
          rows={(ext?.attachments || []).map((a, i) => [
            `${a.filename} (${(a.size_bytes / 1024).toFixed(1)} KB)`,
            <code key="h">{a.sha256}</code>,
            <span key="s">
              {attachments[i]?.error ? (
                <span className="muted">{attachments[i].error}</span>
              ) : (
                <Badge value={attachments[i]?.verdict} />
              )}
            </span>,
          ])}
          empty="No attachments."
        />
      </Section>
      {auth.spf_header && (
        <Section icon={Shield} title="SPF Header">
          <code className="raw">{auth.spf_header}</code>
        </Section>
      )}
      {auth.auth_results && (
        <Section icon={Shield} title="Authentication-Results">
          <code className="raw">{auth.auth_results}</code>
        </Section>
      )}
      {ext?.body_text_sample && (
        <Section icon={FileText} title="Body Sample">
          <p className="preview">{ext.body_text_sample}</p>
        </Section>
      )}
      {item.status === "failed" && (
        <div className="error">
          {(item.errors || []).join(" · ") || "Analysis failed."}
        </div>
      )}
      <a
        className="button"
        href={`${API_BASE_URL}/api/analyses/${item.analysis_id}/report`}
      >
        Download JSON report
      </a>
    </div>
  );
}
function badgeText(value) {
  if (!value) return "none";
  const lower = value.toLowerCase();
  if (lower.includes("fail")) return "fail";
  if (lower.includes("pass")) return "pass";
  return "reported";
}
function SettingsPanel() {
  return (
    <>
      <h1>Settings</h1>
      <div className="card settings">
        <h2>Integration status</h2>
        <p>Keys are server-side only and are never exposed to the browser.</p>
        {[
          "OPENROUTER_API_KEY",
          "VT_API_KEY",
          "IPINFO_TOKEN",
          "DATABASE_URL",
        ].map((x) => (
          <div className="setting" key={x}>
            <code>{x}</code>
            <span>Configured by backend environment</span>
          </div>
        ))}
        <p className="muted">
          Extracted email data may be sent to the configured AI provider. URLs
          and attachment hashes may be queried through external providers.
        </p>
      </div>
    </>
  );
}
createRoot(document.getElementById("root")).render(<App />);