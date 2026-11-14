from pathlib import Path
from collections import Counter
from html import escape
from functools import lru_cache
import base64
import ipaddress
import joblib
import networkx as nx
import numpy as np
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

ROOT = Path(__file__).resolve().parent
MODEL_PATH_CANDIDATES = [
    ROOT / "models" / "SentinelAi_model.joblib",
    ROOT / "SentinelAi_model.joblib",
]

CHUNK_SIZE = 100_000
MAX_GRAPH_EDGES = 2500
MAX_ALERT_ROWS = 5000

st.set_page_config(
    page_title="SentinelAI | Network Security",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Manrope:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');
:root{--bg:#080d19;--s1:#0e1525;--s2:#131c30;--line:#1e2a44;--tx:#e8edf8;--mu:#8795b1;
--ac:#6c8cff;--red:#ff5468;--amb:#ffb347;--grn:#34d1a0;}
.ac{--t:var(--ac)}.red{--t:var(--red)}.amb{--t:var(--amb)}.grn{--t:var(--grn)}.mu{--t:var(--mu)}
.stApp{background:var(--bg);color:var(--tx);font-family:'Manrope',sans-serif}
#MainMenu,footer{visibility:hidden}
header[data-testid="stHeader"]{background:transparent}
.block-container{padding:1.8rem 2.5rem 4rem;max-width:1500px}
p,label,li{color:#b4c0d8}
.mono{font-family:'JetBrains Mono',monospace}
[data-testid="stSidebar"]{background:var(--s1);border-right:1px solid var(--line)}
.brand{display:flex;gap:12px;align-items:center;padding:6px 4px 18px}
.brand .logo{width:42px;height:42px;border-radius:12px;background:#17244a;border:1px solid #2b3f7a;
display:flex;align-items:center;justify-content:center;font-size:1.3rem}
.brand b{display:block;color:var(--tx);font-size:1.05rem;letter-spacing:-.01em}
.brand small{color:var(--mu);font-size:.76rem}
[data-testid="stSidebar"] div[role="radiogroup"]{gap:3px}
[data-testid="stSidebar"] div[role="radiogroup"] label{width:100%;padding:10px 12px;border-radius:10px;
border:1px solid transparent;cursor:pointer;transition:background .15s}
[data-testid="stSidebar"] div[role="radiogroup"] label>div:first-child{display:none}
[data-testid="stSidebar"] div[role="radiogroup"] label:hover{background:var(--s2)}
[data-testid="stSidebar"] div[role="radiogroup"] label:has(input:checked){background:rgba(108,140,255,.14);border-color:rgba(108,140,255,.4)}
[data-testid="stSidebar"] div[role="radiogroup"] label p{color:var(--tx);font-weight:600;font-size:.92rem}
.side-card{background:var(--s2);border:1px solid var(--line);border-radius:12px;padding:12px 14px;margin-top:10px}
.hero{display:flex;justify-content:space-between;align-items:flex-start;gap:24px;margin-bottom:1.4rem}
.hero h1{font-size:2.1rem;font-weight:800;letter-spacing:-.035em;color:var(--tx);margin:0;padding:0}
.hero p{color:var(--mu);margin:.4rem 0 0;max-width:640px;line-height:1.55}
.chips{display:flex;gap:8px;flex-wrap:wrap;padding-top:8px}
.chip{display:inline-block;padding:4px 11px;border-radius:999px;font-size:.76rem;font-weight:700;
color:var(--t);background:color-mix(in srgb,var(--t) 14%,transparent);border:1px solid color-mix(in srgb,var(--t) 38%,transparent)}
.panel{background:var(--s1);border:1px solid var(--line);border-radius:14px;padding:18px 20px}
.kl{color:var(--mu);font-size:.8rem;font-weight:600;margin-bottom:6px}
.kpi{background:var(--s1);border:1px solid var(--line);border-left:3px solid var(--t);border-radius:14px;padding:16px 20px;min-height:118px}
.kn{color:var(--tx);font-size:2rem;font-weight:800;letter-spacing:-.03em;font-family:'JetBrains Mono',monospace;margin-top:4px}
.kh{color:var(--mu);font-size:.78rem;margin-top:4px}
.sec{display:flex;align-items:baseline;gap:12px;margin:1.8rem 0 .8rem}
.sec h3{margin:0;padding:0;font-size:1.12rem;font-weight:700;color:var(--tx);letter-spacing:-.015em}
.sec span{color:var(--mu);font-size:.84rem}
.banner{background:var(--s1);border:1px solid var(--line);border-left:4px solid var(--t);border-radius:14px;padding:22px 26px;margin:.6rem 0 1rem}
.bn-lvl{color:var(--t);font-weight:700;font-size:.85rem}
.bn-title{color:var(--tx);font-size:1.7rem;font-weight:800;letter-spacing:-.03em;margin:4px 0}
.bn-sub{color:var(--mu);font-size:.92rem}
.bar{display:flex;gap:3px;height:12px;border-radius:99px;overflow:hidden;margin-top:18px;background:var(--s2)}
.bar .seg{min-width:4px}
.legend{display:flex;flex-wrap:wrap;gap:6px 16px;margin-top:10px;font-size:.8rem;color:var(--mu)}
.legend i{display:inline-block;width:9px;height:9px;border-radius:3px;margin-right:6px}
.stage{display:flex;gap:12px;margin-top:14px;align-items:flex-start}
.stage i,.step i{flex:none;width:26px;height:26px;border-radius:8px;background:#17244a;border:1px solid #2b3f7a;color:#9db4ff;
font-style:normal;font-weight:700;font-size:.8rem;display:flex;align-items:center;justify-content:center}
.stage b,.step b{display:block;color:var(--tx);font-size:.93rem}
.stage span,.step span{display:block;color:var(--mu);font-size:.82rem;line-height:1.45;margin-top:2px}
.steps{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}
.step{background:var(--s1);border:1px solid var(--line);border-radius:14px;padding:18px;display:flex;flex-direction:column;gap:10px}
.devhead{display:flex;align-items:center;gap:14px;margin:.4rem 0 1rem;font-size:1.5rem;font-weight:700;color:var(--tx)}
.kvgrid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
.kvgrid .panel b{display:block;color:var(--tx);font-size:1.02rem;margin-top:2px;word-break:break-all}
.note{border:1px solid rgba(255,179,71,.35);background:rgba(255,179,71,.07);border-radius:12px;padding:14px 18px;color:#e9c98f;font-size:.88rem;margin-top:1.2rem}
div[data-testid="stPlotlyChart"]{background:var(--s1);border:1px solid var(--line);border-radius:14px;padding:6px;overflow:hidden}
div[data-testid="stFileUploader"]{background:var(--s1);border:1px dashed #34497a;border-radius:14px;padding:14px}
div[data-testid="stFileUploader"] section{background:var(--s2);border-radius:10px}
div[data-testid="stDataFrame"]{border:1px solid var(--line);border-radius:12px;overflow:hidden}
.stButton button,.stDownloadButton button{border-radius:10px;font-weight:700;border:1px solid var(--line);padding:.55rem 1rem}
.stButton button[kind="primary"],.stButton button[data-testid="stBaseButton-primary"]{background:var(--ac);border-color:var(--ac);color:#091022}
.stButton button:focus-visible,.stDownloadButton button:focus-visible{outline:2px solid var(--ac);outline-offset:2px}
.kpi.sm{min-height:96px}.kpi.sm .kn{font-size:1.25rem;word-break:break-all}
.legend.icons{margin:.6rem 0 0;gap:8px 22px}.legend.icons span{display:inline-flex;align-items:center}.legend.icons img{width:24px;height:24px;margin-right:8px}
.guide{display:grid;grid-template-columns:repeat(2,1fr);gap:12px;margin-top:.6rem}.guide .panel b{color:var(--tx);display:block;margin-bottom:4px}.guide .panel span{color:var(--mu);font-size:.86rem;line-height:1.5}
@media(max-width:900px){.guide{grid-template-columns:1fr}}
@media(max-width:900px){.steps,.kvgrid{grid-template-columns:1fr 1fr}.hero{flex-direction:column}.block-container{padding:1.2rem 1rem}}
</style>
""", unsafe_allow_html=True)



def locate_model():
    for candidate in MODEL_PATH_CANDIDATES:
        if candidate.exists():
            return candidate
    return None


@st.cache_resource(show_spinner="Loading SentinelAI models...")
def load_bundle(model_path: str, modified_time: float):
    # modified_time participates in cache invalidation after replacing the model file.
    bundle = joblib.load(model_path)
    required = {"anomaly_pipeline", "attack_pipeline", "features"}
    missing = required.difference(bundle.keys())
    if missing:
        raise KeyError(f"Model bundle is missing keys: {sorted(missing)}")
    return bundle


def find_column(columns, candidates):
    normalized = {str(c).strip().lower().replace("_", " ").replace("-", " "): c
                  for c in columns}
    for candidate in candidates:
        key = candidate.strip().lower().replace("_", " ").replace("-", " ")
        if key in normalized:
            return normalized[key]
    return None


def discover_ip_columns(columns):
    src = find_column(columns, [
        "Source IP",
        "Src IP",
        "srcip",
        "source_ip",
        "src_ip",
        "src ip address",
        "source ip address",
        "source address",
        "src address",
        "Source"
    ])

    dst = find_column(columns, [
        "Destination IP",
        "Dst IP",
        "dstip",
        "destination_ip",
        "dst_ip",
        "dst ip address",
        "destination ip address",
        "destination address",
        "dst address",
        "Destination"
    ])

    return src, dst


def safe_text(value):
    if pd.isna(value):
        return "Unknown"
    return str(value)

def process_uploaded_csv(uploaded_file, bundle):
    features = list(bundle["features"])
    anomaly_pipeline = bundle["anomaly_pipeline"]
    attack_pipeline = bundle["attack_pipeline"]

    uploaded_file.seek(0)
    reader = pd.read_csv(uploaded_file, chunksize=CHUNK_SIZE, low_memory=False)

    total_flows = 0
    benign_flows = 0
    anomaly_flows = 0
    attack_counts = Counter()
    node_flow_counts = Counter()
    node_attack_counts = Counter()
    edge_counts = Counter()
    edge_attack_counts = Counter()
    alert_frames = []
    missing_ip_rows = 0
    detected_src_col = None
    detected_dst_col = None

    progress = st.progress(0, text="Preparing CSV analysis...")
    status = st.empty()

    for chunk_number, chunk in enumerate(reader, start=1):
        total_flows += len(chunk)

        missing_features = [f for f in features if f not in chunk.columns]
        if missing_features:
            progress.empty()
            status.empty()
            raise ValueError(
                "The uploaded CSV does not contain all model features. "
                f"Missing columns: {missing_features[:20]}"
            )

        if chunk_number == 1:
            detected_src_col, detected_dst_col = discover_ip_columns(chunk.columns)
            
        if chunk_number == 1:
            if detected_src_col and detected_dst_col:
                st.info(
                    f"Network endpoints detected: "
                    f"{detected_src_col} → {detected_dst_col}"
                )
            else:
                st.warning(
                    "Network Map unavailable: "
                    f"Source IP: {detected_src_col or 'Not found'} | "
                    f"Destination IP: {detected_dst_col or 'Not found'}"
                )

        X = chunk.loc[:, features]
        predictions = anomaly_pipeline.predict(X)
        is_anomaly = np.asarray(predictions) == -1

        result = pd.DataFrame(index=chunk.index)
        result["status"] = np.where(is_anomaly, "ATTACK", "BENIGN")
        result["attack_type"] = None

        if is_anomaly.any():
            attack_predictions = attack_pipeline.predict(X.loc[is_anomaly])
            result.loc[is_anomaly, "attack_type"] = [
                safe_text(x) for x in attack_predictions
            ]

        benign_flows += int((~is_anomaly).sum())
        anomaly_flows += int(is_anomaly.sum())

        if is_anomaly.any():
            attack_counts.update(result.loc[is_anomaly, "attack_type"].fillna("Unknown"))
            alert_part = chunk.loc[is_anomaly].copy()
            alert_part["SentinelAI Status"] = "ATTACK"
            alert_part["Predicted Attack Type"] = result.loc[is_anomaly, "attack_type"].values
            if len(alert_frames) < MAX_ALERT_ROWS:
                remaining = MAX_ALERT_ROWS - sum(len(x) for x in alert_frames)
                alert_frames.append(alert_part.head(remaining))

        # Build device and connection aggregates when endpoint columns exist.
        if detected_src_col and detected_dst_col:
            src_values = chunk[detected_src_col].astype("string").fillna("Unknown")
            dst_values = chunk[detected_dst_col].astype("string").fillna("Unknown")

            for src, dst, attack_flag in zip(src_values, dst_values, is_anomaly):
                src, dst = str(src), str(dst)
                if src in ("", "Unknown", "<NA>") or dst in ("", "Unknown", "<NA>"):
                    missing_ip_rows += 1
                    continue
                node_flow_counts[src] += 1
                node_flow_counts[dst] += 1
                edge_counts[(src, dst)] += 1
                if attack_flag:
                    edge_attack_counts[(src, dst)] += 1
                if attack_flag:
                    node_attack_counts[src] += 1
                    node_attack_counts[dst] += 1

        status.write(
            f"Processed {total_flows:,} flows · chunk {chunk_number}"
        )
        progress.progress(min(0.99, 1 - (1 / (chunk_number + 1))),
                          text=f"Analyzing chunk {chunk_number}...")

    progress.progress(1.0, text="Analysis completed")
    status.empty()
    progress.empty()

    alerts = pd.concat(alert_frames, ignore_index=True) if alert_frames else pd.DataFrame()
    return {
        "total_flows": total_flows,
        "benign_flows": benign_flows,
        "anomaly_flows": anomaly_flows,
        "attack_counts": attack_counts,
        "node_flow_counts": node_flow_counts,
        "node_attack_counts": node_attack_counts,
        "edge_counts": edge_counts,
        "edge_attack_counts": edge_attack_counts,
        "alerts": alerts,
        "src_col": detected_src_col,
        "dst_col": detected_dst_col,
        "missing_ip_rows": missing_ip_rows,
    }


# ───────────────────────── UI helpers ─────────────────────────
RED, AMB, GRN, ACC = "#ff5468", "#ffb347", "#35d1a0", "#6c8cff"
PALETTE = [RED, AMB, ACC, "#b07cff", "#38bdf8", "#f472b6", "#a3e635",
           "#fb923c", "#2dd4bf", "#e879f9", "#facc15", "#94a3b8"]


def H(s):
    return "".join(line.strip() for line in s.splitlines())


def md(s):
    st.markdown(H(s), unsafe_allow_html=True)


def chip(text, tone="mu"):
    return f'<span class="chip {tone}">{text}</span>'


def section(title, sub=""):
    md(f'<div class="sec"><h3>{title}</h3><span>{sub}</span></div>')


def kpi(label, value, hint="", tone="ac", small=False):
    md(f'<div class="kpi {tone}{" sm" if small else ""}"><div class="kl">{label}</div>'
       f'<div class="kn">{value}</div><div class="kh">{hint}</div></div>')


def risk_level(rate):
    if rate == 0:
        return "Clear", "grn"
    if rate < 1:
        return "Low", "ac"
    if rate < 10:
        return "Elevated", "amb"
    return "High", "red"


def theme(fig, height, **layout):
    fig.update_layout(
        height=height, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Manrope, sans-serif", color="#c5d0e6", size=13),
        margin=dict(l=16, r=16, t=36, b=16),
        hoverlabel=dict(bgcolor="#131c30", bordercolor="#2a3a5c",
                        font=dict(family="JetBrains Mono, monospace", size=12, color="#e8edf8")),
        **layout,
    )
    return fig


def show(fig):
    st.plotly_chart(fig, use_container_width=True, theme=None,
                    config={"displaylogo": False, "displayModeBar": False})


KIND_LABEL = {"workstation": "Workstation", "server": "Server", "gateway": "Gateway", "internet": "Internet host"}
PRIVATE_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
GLYPH = {
    "workstation": '<rect x="15" y="17" width="34" height="22" rx="3"/><path d="M27 48h10M32 39v9"/>',
    "server": '<rect x="15" y="14" width="34" height="11" rx="2"/><rect x="15" y="27" width="34" height="11" rx="2"/>'
              '<rect x="15" y="40" width="34" height="11" rx="2"/><path d="M21 19.5h.01M21 32.5h.01M21 45.5h.01"/>',
    "gateway": '<rect x="12" y="36" width="40" height="14" rx="4"/><path d="M21 36V21M43 36V21M24 43h.01M31 43h.01"/>',
    "internet": '<circle cx="32" cy="32" r="18"/><ellipse cx="32" cy="32" rx="8" ry="18"/><path d="M14 32h36"/>',
}


def device_kind(ip, in_flows, out_flows):
    """Best-effort role from the IP only: public = internet, .1 = gateway, mostly receiving = server."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "workstation"
    if not any(addr in net for net in PRIVATE_NETS):
        return "internet"
    if ip.endswith(".1"):
        return "gateway"
    return "server" if in_flows > out_flows else "workstation"


def device_roles(analysis):
    in_f, out_f = Counter(), Counter()
    for (s, d), w in analysis["edge_counts"].items():
        out_f[s] += w
        in_f[d] += w
    return {ip: device_kind(ip, in_f[ip], out_f[ip]) for ip in analysis["node_flow_counts"]}


@lru_cache(maxsize=16)
def device_icon(kind, flagged):
    c, bg = (RED, "#2a1119") if flagged else (GRN, "#0f2a25")
    badge = (f'<circle cx="52" cy="12" r="9" fill="{RED}" stroke="#080d19" stroke-width="2"/>'
             '<path d="M52 7.5v5.5M52 16h.01" stroke="#fff" stroke-width="2.4" stroke-linecap="round"/>') if flagged else ""
    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect x="3" y="3" width="58" height="58" rx="14" '
           f'fill="{bg}" stroke="{c}" stroke-width="2.5"/><g fill="none" stroke="{c}" stroke-width="2.6" '
           f'stroke-linecap="round" stroke-linejoin="round">{GLYPH[kind]}</g>{badge}</svg>')
    return "data:image/svg+xml;base64," + base64.b64encode(svg.encode()).decode()


def topology_legend():
    items = "".join(f'<span><img src="{device_icon(k, False)}"/>{v}</span>' for k, v in KIND_LABEL.items())
    md(f'<div class="legend icons">{items}<span><img src="{device_icon("workstation", True)}"/>Involved in flagged flows</span>'
       f'<span><b style="color:{RED}">━▶</b>&nbsp;Flagged connection</span>'
       '<span><b style="color:#829bcd">━▶</b>&nbsp;Normal connection (thicker = more flows)</span></div>')


def make_network_figure(analysis):
    edges = analysis["edge_counts"]
    node_flows = analysis["node_flow_counts"]
    node_attacks = analysis["node_attack_counts"]
    edge_att = analysis.get("edge_attack_counts") or Counter()
    if not edges:
        return None

    graph = nx.DiGraph()
    for (src, dst), weight in edges.most_common(MAX_GRAPH_EDGES):
        graph.add_edge(src, dst, weight=weight)
    n = graph.number_of_nodes()
    if n == 0:
        return None

    und = graph.to_undirected()
    try:  # deterministic layouts keep the map stable between reruns
        raw = nx.kamada_kawai_layout(und) if n <= 40 else nx.spring_layout(und, seed=17, k=0.8, iterations=45)
    except Exception:
        raw = nx.spring_layout(und, seed=17)
    xs, ys = [p[0] for p in raw.values()], [p[1] for p in raw.values()]

    def scale(v, lo, hi, span):
        return 0.0 if hi == lo else (v - lo) / (hi - lo) * 2 * span - span

    pos = {k: (scale(p[0], min(xs), max(xs), 1.5), scale(p[1], min(ys), max(ys), 0.95)) for k, p in raw.items()}
    roles = device_roles(analysis)

    px = 50 if n <= 16 else 42 if n <= 30 else 32 if n <= 60 else 24
    size = px * 2.7 / 560            # icon size in axis units (y-range 2.7 over ~560 px)
    maxw = max(w for _, _, w in graph.edges(data="weight"))
    use_arrows = graph.number_of_edges() <= 120
    fig, annots, groups = go.Figure(), [], {}
    mx, my, mt = [], [], []

    for s, d, w in graph.edges(data="weight"):
        hot = edge_att.get((s, d), 0) > 0 if edge_att else bool(node_attacks.get(s) or node_attacks.get(d))
        width = 1 + 3.2 * (w / maxw) ** 0.5
        color = "rgba(255,84,104,.65)" if hot else "rgba(130,155,205,.45)"
        (x0, y0), (x1, y1) = pos[s], pos[d]
        if use_arrows:
            annots.append(dict(x=x1, y=y1, ax=x0, ay=y0, xref="x", yref="y", axref="x", ayref="y", text="",
                               showarrow=True, arrowhead=3, arrowsize=1.1, arrowwidth=width, arrowcolor=color,
                               standoff=px / 2 + 3, startstandoff=px / 2 + 3))
        else:
            g = groups.setdefault((hot, round(width)), ([], [], color, width))
            g[0].extend([x0, x1, None])
            g[1].extend([y0, y1, None])
        mx.append((x0 + x1) / 2)
        my.append((y0 + y1) / 2)
        mt.append(f"<b>{escape(s)} → {escape(d)}</b><br>Flows: {w:,}<br>Flagged: {edge_att.get((s, d), 0):,}")

    for gx, gy, color, width in groups.values():
        fig.add_trace(go.Scatter(x=gx, y=gy, mode="lines", line=dict(width=width, color=color),
                                 hoverinfo="none", showlegend=False))
    fig.add_trace(go.Scatter(x=mx, y=my, mode="markers", marker=dict(size=14, color="rgba(0,0,0,0)"),
                             text=mt, hovertemplate="%{text}<extra></extra>", showlegend=False))

    nodes = list(graph.nodes())
    node_text = [f"<b>{escape(v)}</b><br>{KIND_LABEL[roles[v]]}<br>Flows: {node_flows.get(v, 0):,}"
                 f"<br>Flagged: {node_attacks.get(v, 0):,}" for v in nodes]
    images = []
    if n <= 150:  # draw real device icons
        for v in nodes:
            images.append(dict(source=device_icon(roles[v], bool(node_attacks.get(v))), xref="x", yref="y",
                               x=pos[v][0], y=pos[v][1], sizex=size, sizey=size,
                               xanchor="center", yanchor="middle", layer="above"))
        marker = dict(size=px, color="rgba(0,0,0,0)")
    else:  # too many devices for icons: fall back to dots
        marker = dict(size=[min(30, 10 + np.log1p(node_flows.get(v, 0)) * 2) for v in nodes],
                      color=[RED if node_attacks.get(v) else GRN for v in nodes],
                      line=dict(width=1.2, color="#0b1120"))
    fig.add_trace(go.Scatter(x=[pos[v][0] for v in nodes], y=[pos[v][1] for v in nodes], mode="markers",
                             marker=marker, text=node_text, hovertemplate="%{text}<extra></extra>", showlegend=False))
    if n <= 30:
        fig.add_trace(go.Scatter(x=[pos[v][0] for v in nodes], y=[pos[v][1] - size * 0.78 for v in nodes],
                                 mode="text", text=nodes, textposition="middle center", hoverinfo="skip",
                                 textfont=dict(family="JetBrains Mono, monospace", size=11, color="#c5d0e6"),
                                 showlegend=False))
    theme(fig, 640, images=images, annotations=annots, hovermode="closest",
          xaxis=dict(visible=False, range=[-1.95, 1.95], constrain="domain"),
          yaxis=dict(visible=False, range=[-1.35, 1.35], scaleanchor="x", scaleratio=1, constrain="domain"))
    return fig


def findings(analysis):
    """Busiest link, top sender of flagged flows, most targeted device."""
    ea = analysis.get("edge_attack_counts") or Counter()
    sent, got = Counter(), Counter()
    for (s, d), k in ea.items():
        sent[s] += k
        got[d] += k
    busiest = analysis["edge_counts"].most_common(1)
    return busiest, sent.most_common(1), got.most_common(1)


def findings_row(analysis):
    busiest, sender, target = findings(analysis)
    a, b, c = st.columns(3)
    with a:
        kpi("Busiest link", escape(f"{busiest[0][0][0]} → {busiest[0][0][1]}") if busiest else "—",
            f"{busiest[0][1]:,} flows" if busiest else "No endpoint columns", "ac", small=True)
    with b:
        kpi("Top source of flagged flows", escape(sender[0][0]) if sender else "—",
            f"{sender[0][1]:,} flagged flows sent" if sender else "Nothing flagged", "red" if sender else "grn", small=True)
    with c:
        kpi("Most targeted device", escape(target[0][0]) if target else "—",
            f"{target[0][1]:,} flagged flows received" if target else "Nothing flagged", "amb" if target else "grn", small=True)


def at_risk_table(analysis, limit=8):
    roles = device_roles(analysis)
    rows = [{"IP address": ip, "Role": KIND_LABEL[roles[ip]], "Flagged flows": k,
             "Flagged share": k / analysis["node_flow_counts"][ip] * 100}
            for ip, k in analysis["node_attack_counts"].most_common(limit)]
    return pd.DataFrame(rows)



GUIDE = [
    ("Sidebar", "Switches between the six workspaces. The cards under it show whether the detection models loaded and that the app works on uploaded files only."),
    ("Header chips", "Quick status: models ready or missing, and offline analysis mode."),
    ("Upload and Analyze", "Drop a CSV that has every model feature plus Source IP and Destination IP. Analyze runs both stages. Reset clears the current results."),
    ("Risk banner", "Shows the share of flows that Isolation Forest flagged and a level: Clear, Low (under 1%), Elevated (1–10%) or High (over 10%). It is a flagged share, not proof of an attack."),
    ("Attack-type strip", "The coloured bar splits the flagged flows by the attack type Random Forest predicted. Colours match the Attack categories chart."),
    ("KPI cards", "Total flows read, unique devices, flagged flows and flows left unflagged."),
    ("Key findings", "The busiest link, the device that sent the most flagged flows, and the device that received the most."),
    ("Network topology", "Each icon is a device. The role is inferred from the IP: public address = internet host, address ending in .1 = gateway, private host that mostly receives = server, otherwise workstation. A red badge means the device took part in a flagged flow."),
    ("Arrows", "An arrow goes from source to destination. Thicker means more flows. Red means that connection carried at least one flagged flow. Hover an arrow or an icon for details."),
    ("Detection split and categories", "The donut compares flagged and unflagged flows. The bars rank predicted attack types."),
    ("Devices to review and ports", "Devices ranked by flagged flows, and the destination ports most often seen in flagged flows."),
    ("Threat feed", "The flagged rows (up to 5,000) with search, attack-type filter and CSV download."),
    ("Device inspector", "Pick one IP to see its role, flow counts, top connections and its flagged flows."),
    ("Model and data", "How the two stages work, the columns the app detected, and how many rows had no usable IPs."),
]


def donut_figure(attacks, benign, rate):
    fig = go.Figure(go.Pie(
        labels=["Flagged", "Not flagged"], values=[attacks, benign], hole=0.76, sort=False,
        marker=dict(colors=[RED, GRN], line=dict(color="#0e1525", width=3)),
        textinfo="none", hovertemplate="%{label}: %{value:,} (%{percent})<extra></extra>",
    ))
    fig.add_annotation(text=f"<b>{rate:.1f}%</b>", showarrow=False, font=dict(size=30, color="#e8edf8"))
    return theme(fig, 290, legend=dict(orientation="h", y=-0.02, x=0.5, xanchor="center"))


def attack_bar(attack_counts, colors):
    items = attack_counts.most_common(12)[::-1]
    fig = go.Figure(go.Bar(
        x=[v for _, v in items], y=[k for k, _ in items], orientation="h",
        marker=dict(color=[colors.get(k, ACC) for k, _ in items]),
        text=[f"{v:,}" for _, v in items], textposition="outside", cliponaxis=False,
        hovertemplate="%{y}: %{x:,}<extra></extra>",
    ))
    return theme(fig, 80 + 34 * len(items), bargap=0.35,
                 xaxis=dict(visible=False), yaxis=dict(tickfont=dict(size=13)))


# ───────────────────────── Sidebar ─────────────────────────
model_path = locate_model()
bundle, model_error = None, None
if model_path:
    try:
        bundle = load_bundle(str(model_path), model_path.stat().st_mtime)
    except Exception as exc:
        model_error = str(exc)

NAV = {
    "Overview": "▦  Overview",
    "Network Map": "◎  Network map",
    "Threat Feed": "⚑  Threat feed",
    "Device Inspector": "⌕  Device inspector",
    "Model & Data": "ⓘ  Model & data",
    "Guide": "?  Guide",
}

with st.sidebar:
    md('<div class="brand"><div class="logo">🛡️</div><div><b>SentinelAI</b>'
       '<small>Network intrusion detection</small></div></div>')
    page = st.radio("Navigation", list(NAV), format_func=NAV.get, label_visibility="collapsed")
    if bundle:
        md(f'<div class="side-card"><div class="kl">Detection models</div>{chip("Ready", "grn")}'
           f'<div class="kh mono">{escape(model_path.name)}</div></div>')
    elif model_error:
        md(f'<div class="side-card"><div class="kl">Detection models</div>{chip("Load failed", "red")}'
           f'<div class="kh">{escape(model_error)}</div></div>')
    else:
        md(f'<div class="side-card"><div class="kl">Detection models</div>{chip("Not found", "amb")}'
           '<div class="kh">Expected at models/SentinelAi_model.joblib</div></div>')
    md(f'<div class="side-card"><div class="kl">Mode</div>{chip("Offline CSV", "ac")}'
       '<div class="kh">Analyzes uploaded flow records. It does not capture live packets.</div></div>')

# ───────────────────────── Header & upload ─────────────────────────
status_chip = chip("Models ready", "grn") if bundle else chip("Model missing", "amb")
md(f'''<div class="hero"><div><h1>Network security command center</h1>
<p>Upload network-flow records, run the two-stage detection pipeline, and see which devices are involved in suspicious traffic.</p></div>
<div class="chips">{status_chip}{chip("Offline analysis", "ac")}</div></div>''')

upload_col, info_col = st.columns([1.5, 1])
with upload_col:
    uploaded_file = st.file_uploader(
        "Upload network traffic CSV", type=["csv"],
        help="CSV must contain every feature used during model training.",
    )
with info_col:
    md('''<div class="panel"><div class="kl">Detection pipeline</div>
<div class="stage"><i>1</i><div><b>Anomaly detection</b><span>Isolation Forest flags unusual flows.</span></div></div>
<div class="stage"><i>2</i><div><b>Attack classification</b><span>Random Forest assigns an attack type to each flagged flow.</span></div></div></div>''')

if "analysis" not in st.session_state:
    st.session_state.analysis = None
    st.session_state.file_name = None

run_col, reset_col, _ = st.columns([1, 1, 3])
with run_col:
    analyze_clicked = st.button("Analyze file", type="primary", use_container_width=True,
                                disabled=(uploaded_file is None or bundle is None))
with reset_col:
    if st.button("Reset", use_container_width=True):
        st.session_state.analysis = None
        st.session_state.file_name = None
        st.rerun()

if analyze_clicked:
    try:
        with st.spinner("Running SentinelAI inference..."):
            analysis = process_uploaded_csv(uploaded_file, bundle)
        st.session_state.analysis = analysis
        st.session_state.file_name = uploaded_file.name
        st.success("Analysis complete.")
    except Exception as exc:
        st.error(f"Analysis failed: {exc}")

analysis = st.session_state.analysis

if uploaded_file is not None and bundle is None:
    st.warning("Add the trained model bundle at models/SentinelAi_model.joblib to enable analysis.")

if page == "Guide":
    section("How to read this dashboard", "Every part of the screen, in the order you meet it")
    topology_legend()
    md('<div class="guide">' + "".join(f'<div class="panel"><b>{t}</b><span>{d}</span></div>' for t, d in GUIDE) + '</div>')
    st.stop()

if analysis is None:
    section("What happens when you analyze a file")
    md('''<div class="steps">
<div class="step"><i>1</i><b>Validate</b><span>Checks that the CSV contains every feature the model was trained on.</span></div>
<div class="step"><i>2</i><b>Detect</b><span>Reads the file in chunks and flags anomalous flows with Isolation Forest.</span></div>
<div class="step"><i>3</i><b>Classify</b><span>Random Forest names the attack type of each flagged flow.</span></div>
<div class="step"><i>4</i><b>Map and report</b><span>Builds the device topology, threat feed and per-device activity.</span></div></div>''')
    st.stop()

# ───────────────────────── Results ─────────────────────────
total = analysis["total_flows"]
attacks = analysis["anomaly_flows"]
benign = analysis["benign_flows"]
devices = len(analysis["node_flow_counts"])
attack_rate = (attacks / total * 100) if total else 0.0
colors = {k: PALETTE[i % len(PALETTE)] for i, (k, _) in enumerate(analysis["attack_counts"].most_common())}

md(f'<div class="chips" style="margin:1.4rem 0 .2rem">{chip(escape(str(st.session_state.file_name)), "ac")}'
   f'{chip(f"{total:,} flows", "mu")}{chip(f"{devices:,} devices", "mu")}</div>')

if page == "Overview":
    lvl, tone = risk_level(attack_rate)
    top = analysis["attack_counts"].most_common(1)
    top_txt = f" Most common type: {escape(top[0][0])}." if top else ""
    bar = (f'<div class="bar"><div class="seg" style="width:{attack_rate:.3f}%;background:{RED}"></div>'
           f'<div class="seg" style="flex:1;background:{GRN};opacity:.55"></div></div>')
    strip, legend = "", ""
    if analysis["attack_counts"]:
        segs = "".join(f'<div class="seg" style="flex:{v};background:{colors[k]}" title="{escape(k)}: {v:,}"></div>'
                       for k, v in analysis["attack_counts"].most_common())
        strip = f'<div class="kl" style="margin-top:18px">Flagged flows by attack type</div><div class="bar" style="margin-top:0">{segs}</div>'
        legend = '<div class="legend">' + "".join(
            f'<span><i style="background:{colors[k]}"></i>{escape(k)} · {v:,}</span>'
            for k, v in analysis["attack_counts"].most_common(8)) + "</div>"
    md(f'''<div class="banner {tone}"><div class="bn-lvl">{lvl} flagged share</div>
<div class="bn-title">{attack_rate:.2f}% of flows were flagged</div>
<div class="bn-sub">Stage 1 flagged {attacks:,} of {total:,} flows across {devices:,} devices.{top_txt}</div>
{bar}{strip}{legend}</div>''')

    c1, c2, c3, c4 = st.columns(4)
    with c1: kpi("Total flows", f"{total:,}", "Rows processed", "ac")
    with c2: kpi("Devices observed", f"{devices:,}", "Unique source and destination IPs", "ac")
    with c3: kpi("Flows flagged", f"{attacks:,}", f"{attack_rate:.2f}% of uploaded flows", "red" if attacks else "grn")
    with c4: kpi("Not flagged", f"{benign:,}", "Classified as normal by Isolation Forest", "grn")

    section("Key findings", "Where the flagged traffic comes from and where it goes")
    findings_row(analysis)

    left, right = st.columns([1.45, 1])
    with left:
        section("Network topology", "Icons are devices · arrows show traffic direction")
        fig = make_network_figure(analysis)
        if fig:
            show(fig)
            topology_legend()
        else:
            st.info("No usable source/destination IP columns were found in this CSV.")
    with right:
        section("Detection split")
        show(donut_figure(attacks, benign, attack_rate))
        section("Attack categories")
        if analysis["attack_counts"]:
            show(attack_bar(analysis["attack_counts"], colors))
        else:
            st.success("No flows were flagged in this file.")

    b1, b2 = st.columns([1.3, 1])
    with b1:
        section("Devices to review", "Ranked by flagged flows")
        risk = at_risk_table(analysis)
        if risk.empty:
            st.success("No device was involved in a flagged flow.")
        else:
            st.dataframe(risk, use_container_width=True, hide_index=True,
                         column_config={"Flagged share": st.column_config.ProgressColumn(
                             "Flagged share", format="%.1f%%", min_value=0, max_value=100)})
    with b2:
        section("Targeted ports", "Destination ports in flagged flows")
        al = analysis["alerts"]
        pcol = find_column(al.columns, ["Dst Port", "Destination Port"]) if not al.empty else None
        if pcol:
            show(attack_bar(Counter({f"Port {k}": int(v) for k, v in al[pcol].value_counts().head(8).items()}), {}))
        else:
            st.info("No destination-port column in the flagged flows.")

elif page == "Network Map":
    section("Interactive network topology", "Red: involved in at least one flagged flow · Green: no flagged flows in this file")
    fig = make_network_figure(analysis)
    if fig:
        show(fig)
        topology_legend()
        section("Key findings")
        findings_row(analysis)
        section("Most active devices")
        roles = device_roles(analysis)
        rows = []
        for ip, count in analysis["node_flow_counts"].most_common(30):
            flagged = analysis["node_attack_counts"].get(ip, 0)
            rows.append({"IP address": ip, "Role": KIND_LABEL[roles[ip]], "Observed flows": count, "Flagged flows": flagged,
                         "Flagged share": flagged / count * 100 if count else 0.0})
        st.dataframe(
            pd.DataFrame(rows), use_container_width=True, hide_index=True,
            column_config={"Flagged share": st.column_config.ProgressColumn(
                "Flagged share", format="%.1f%%", min_value=0, max_value=100)},
        )
    else:
        st.warning("The network map needs source and destination IP columns. "
                   "The model can still classify flows without them, but cannot build device relationships.")
        st.write("Recognized columns: Source IP / Src IP and Destination IP / Dst IP.")

elif page == "Threat Feed":
    section("Detected suspicious flows")
    alerts = analysis["alerts"]
    if alerts.empty:
        st.success("No flows were flagged by Isolation Forest in this file.")
    else:
        f1, f2 = st.columns([2, 1.3])
        search = f1.text_input("Search", placeholder="Filter by IP, port, or attack type")
        type_col = "Predicted Attack Type"
        types = sorted(alerts[type_col].dropna().astype(str).unique()) if type_col in alerts else []
        chosen = f2.multiselect("Attack type (all if empty)", types)
        filtered = alerts
        if chosen:
            filtered = filtered[filtered[type_col].astype(str).isin(chosen)]
        if search:
            mask = filtered.astype(str).apply(
                lambda col: col.str.contains(search, case=False, na=False)).any(axis=1)
            filtered = filtered[mask]
        lead = [c for c in [type_col, analysis["src_col"], analysis["dst_col"]] if c and c in filtered.columns]
        view = filtered[lead + [c for c in filtered.columns if c not in lead]]
        k1, k2, k3 = st.columns(3)
        with k1: kpi("Showing", f"{len(filtered):,}", "Rows matching the filters", "ac")
        with k2: kpi("Retained for review", f"{len(alerts):,}", f"Capped at {MAX_ALERT_ROWS:,} rows", "amb")
        with k3: kpi("Attack types", f"{len(types):,}", "Distinct predicted categories", "red")
        st.write("")
        st.dataframe(view, use_container_width=True, height=520)
        st.download_button("Download flagged flows (CSV)", data=filtered.to_csv(index=False).encode("utf-8"),
                           file_name="sentinelai_flagged_flows.csv", mime="text/csv")

elif page == "Device Inspector":
    section("Device inspector")
    ips = sorted(analysis["node_flow_counts"].keys())
    if not ips:
        st.warning("No device IPs were extracted. Check the CSV endpoint column names.")
    else:
        selected_ip = st.selectbox("Select a device IP", ips)
        flow_count = analysis["node_flow_counts"].get(selected_ip, 0)
        flagged_count = analysis["node_attack_counts"].get(selected_ip, 0)
        badge = chip("Review", "red") if flagged_count else chip("No alerts", "grn")
        kind = device_roles(analysis).get(selected_ip, "workstation")
        md(f'<div class="devhead"><img src="{device_icon(kind, bool(flagged_count))}" style="width:46px;height:46px"/>'
           f'<span class="mono">{escape(selected_ip)}</span>{badge}{chip(KIND_LABEL[kind], "ac")}</div>')
        a, b, c = st.columns(3)
        with a: kpi("Observed flows", f"{flow_count:,}", "Flows involving this IP", "ac")
        with b: kpi("Flagged flows", f"{flagged_count:,}", "Associated anomalous flows", "red" if flagged_count else "grn")
        with c: kpi("Flagged share", f"{(flagged_count / flow_count * 100 if flow_count else 0):.1f}%", "Of this device's flows", "amb")

        peers = Counter()
        for (s, d), n in analysis["edge_counts"].items():
            if s == selected_ip:
                peers[(d, "Outbound")] += n
            elif d == selected_ip:
                peers[(s, "Inbound")] += n
        left, right = st.columns([1, 1.6])
        with left:
            section("Top connections")
            if peers:
                st.dataframe(pd.DataFrame([{"Peer": p, "Direction": dr, "Flows": n}
                                           for (p, dr), n in peers.most_common(15)]),
                             use_container_width=True, hide_index=True)
            else:
                st.info("No connections recorded for this device.")
        with right:
            section("Flagged flows involving this device")
            alerts = analysis["alerts"]
            if not alerts.empty and analysis["src_col"] and analysis["dst_col"]:
                src_col, dst_col = analysis["src_col"], analysis["dst_col"]
                dev = alerts[(alerts[src_col].astype(str) == selected_ip) |
                             (alerts[dst_col].astype(str) == selected_ip)]
                if dev.empty:
                    st.info("No flagged flow for this device is present in the retained alert sample.")
                else:
                    st.dataframe(dev, use_container_width=True, height=400)
            else:
                st.info("No flagged flows are available for this device.")

elif page == "Model & Data":
    section("Model and dataset details")
    c1, c2, c3 = st.columns(3)
    c1.markdown(H('<div class="panel"><div class="kl">Stage 1</div><b style="color:#e8edf8">Isolation Forest</b>'
                  '<p style="margin-top:8px;font-size:.88rem">Marks each flow as normal or anomalous. '
                  'The dashboard shows -1 as ATTACK and 1 as BENIGN.</p></div>'), unsafe_allow_html=True)
    c2.markdown(H('<div class="panel"><div class="kl">Stage 2</div><b style="color:#e8edf8">Random Forest</b>'
                  '<p style="margin-top:8px;font-size:.88rem">Runs only on flows flagged by Stage 1 '
                  'and predicts their attack category.</p></div>'), unsafe_allow_html=True)
    c3.markdown(H('<div class="panel"><div class="kl">Processing</div><b style="color:#e8edf8">Chunked CSV reads</b>'
                  '<p style="margin-top:8px;font-size:.88rem">The file is read in chunks to limit memory use. '
                  'The map comes from IP relationships in the file.</p></div>'), unsafe_allow_html=True)
    section("This run")
    kv = [("Model bundle", model_path.name if model_path else "Not found"),
          ("Expected features", f"{len(bundle['features'])}" if bundle else "Unknown"),
          ("Rows processed", f"{total:,}"),
          ("Source IP column", analysis["src_col"] or "Not found"),
          ("Destination IP column", analysis["dst_col"] or "Not found"),
          ("Rows missing endpoints", f"{analysis['missing_ip_rows']:,}")]
    md('<div class="kvgrid">' + "".join(
        f'<div class="panel"><div class="kl">{k}</div><b class="mono">{escape(str(v))}</b></div>' for k, v in kv) + '</div>')
    md('<div class="note">A green device means no flow involving it was flagged in this file. '
       'It does not prove the device is secure. This is offline analysis, not live monitoring.</div>')

st.markdown("<div style='height:2rem'></div>", unsafe_allow_html=True)
st.caption("SentinelAI · Offline network traffic analysis · Model outputs are predictions and need analyst review.")