#!/usr/bin/env python3
"""
dashboard.py (Management Plane) — real-time attack visualization
-----------------------------------------------------------------
Βελτιωμένο dashboard για τη διπλωματική:
  - Packet rate chart (log scale) — φαίνεται καθαρά το SYN flood spike
  - Attack alert banner + phase badge
  - Σταθερή τοπολογία (preset layout) με OVS switch στο κέντρο
  - Stat cards + blocked host pills + event log
  - dcc.Store για rolling 90s history (client-side, no DB needed)

Scalability note: για >50 hosts θα χρειαστεί:
  - WebSocket (Flask-SocketIO) αντί polling
  - Redis/InfluxDB για history αντί dcc.Store
  - Pagination στο event log
"""

import os
import time

import dash
import dash_cytoscape as cyto
import plotly.graph_objects as go
import requests
from dash import Input, Output, State, dcc, html

CONTROLLER_URL = os.environ.get("CONTROLLER_URL", "http://127.0.0.1:9000")
MAX_PTS = 60   # rolling window ≈ 90 s at 1.5 s refresh

# ── Color palette per host IP ────────────────────────────────────────────────
_COLORS = {
    "10.0.0.1": "#4C72B0",   # blue
    "10.0.0.2": "#55A868",   # green
    "10.0.0.3": "#8172B2",   # purple
    "10.0.0.4": "#64B5CD",   # cyan
    "10.0.0.5": "#DD8452",   # orange — victim
    "10.0.0.6": "#C44E52",   # red    — attacker
}

# ── Cytoscape stylesheet ──────────────────────────────────────────────────────
STYLESHEET = [
    {"selector": "node", "style": {
        "label": "data(label)", "font-size": "11px", "color": "#fff",
        "text-valign": "center", "text-halign": "center",
        "width": 54, "height": 54,
        "background-color": "#4C72B0", "border-width": 2, "border-color": "#2A4880",
        "font-weight": "bold",
    }},
    {"selector": ".switch", "style": {
        "shape": "rectangle", "background-color": "#555",
        "width": 74, "height": 44, "font-size": "12px",
    }},
    {"selector": ".controller", "style": {
        "shape": "diamond", "background-color": "#1F4E79",
        "width": 72, "height": 72, "font-size": "11px",
    }},
    # Per-host colors
    {"selector": ".h1", "style": {"background-color": "#4C72B0", "border-color": "#2A4880"}},
    {"selector": ".h2", "style": {"background-color": "#55A868", "border-color": "#2A6038"}},
    {"selector": ".h3", "style": {"background-color": "#8172B2", "border-color": "#4A3A80"}},
    {"selector": ".h4", "style": {"background-color": "#64B5CD", "border-color": "#3070A0"}},
    {"selector": ".h5", "style": {"background-color": "#DD8452", "border-color": "#994422"}},
    {"selector": ".h6", "style": {"background-color": "#C44E52", "border-color": "#7A0000"}},
    {"selector": ".blocked", "style": {
        "background-color": "#C44E52", "border-color": "#7A0000",
        "border-width": 5, "font-weight": "bold",
    }},
    # Edges
    {"selector": "edge", "style": {
        "curve-style": "bezier", "target-arrow-shape": "triangle",
        "line-color": "#CCC", "target-arrow-color": "#CCC", "width": 2,
    }},
    {"selector": ".infra", "style": {
        "line-color": "#DDD", "target-arrow-shape": "none", "width": 1,
    }},
    {"selector": ".active-edge", "style": {
        "line-color": "#4C72B0", "target-arrow-color": "#4C72B0", "width": 3,
    }},
    {"selector": ".attack-edge", "style": {
        "line-color": "#C44E52", "target-arrow-color": "#C44E52",
        "width": 5, "line-style": "dashed",
    }},
]

# ── Fixed node positions (preset layout → stable, no jumping) ────────────────
POSITIONS = {
    "controller": {"x": 265, "y":  30},
    "s1":         {"x": 265, "y": 180},
    "h1":         {"x":  30, "y": 360},
    "h2":         {"x": 110, "y": 415},
    "h3":         {"x": 200, "y": 445},
    "h4":         {"x": 330, "y": 445},
    "h5":         {"x": 420, "y": 415},
    "h6":         {"x": 500, "y": 360},
}

# ── Dash app ─────────────────────────────────────────────────────────────────
app = dash.Dash(__name__)
app.title = "SDN Defense Dashboard"

app.layout = html.Div(
    style={"fontFamily": "'Segoe UI', Arial, sans-serif", "margin": "0", "background": "#F0F4F8"},
    children=[

        # ── Header ──────────────────────────────────────────────────────────
        html.Div(
            style={"background": "#1F4E79", "color": "white", "padding": "12px 24px",
                   "display": "flex", "justifyContent": "space-between", "alignItems": "center"},
            children=[
                html.Div([
                    html.H2("SDN Defense Dashboard — Global Network View",
                            style={"margin": "0", "fontSize": "20px"}),
                    html.Span("Isolation Forest · Mininet + OVS · Real-time Anomaly Detection",
                              style={"fontSize": "12px", "opacity": "0.8"}),
                ]),
                html.Div(id="phase-badge"),
            ],
        ),

        # ── Attack alert banner (hidden when Normal) ─────────────────────────
        html.Div(id="alert-banner"),

        # ── 3-column main layout ─────────────────────────────────────────────
        html.Div(
            style={"display": "flex", "gap": "10px", "padding": "10px"},
            children=[

                # Topology graph
                html.Div(
                    style={"flex": "2", "background": "white", "borderRadius": "8px",
                           "border": "1px solid #DDD", "padding": "12px"},
                    children=[
                        html.H4("Network Topology",
                                style={"margin": "0 0 6px", "color": "#1F4E79", "fontSize": "13px"}),
                        cyto.Cytoscape(
                            id="topology-graph",
                            layout={"name": "preset"},
                            style={"width": "100%", "height": "500px"},
                            stylesheet=STYLESHEET,
                            elements=[],
                            userZoomingEnabled=True,
                        ),
                    ],
                ),

                # Packet rate chart
                html.Div(
                    style={"flex": "3", "background": "white", "borderRadius": "8px",
                           "border": "1px solid #DDD", "padding": "12px"},
                    children=[
                        html.H4("Packet Rate per Host  (pkts / 5s window, log scale)",
                                style={"margin": "0 0 6px", "color": "#1F4E79", "fontSize": "13px"}),
                        dcc.Graph(id="rate-chart", style={"height": "500px"},
                                  config={"displayModeBar": False}),
                    ],
                ),

                # Stats panel
                html.Div(
                    style={"flex": "1", "background": "white", "borderRadius": "8px",
                           "border": "1px solid #DDD", "padding": "16px",
                           "overflowY": "auto", "maxHeight": "530px"},
                    children=[html.Div(id="stats-panel")],
                ),
            ],
        ),

        # ── State ────────────────────────────────────────────────────────────
        dcc.Store(id="history",
                  data={"t": [], "rates": {}, "blocked": [], "t0": None}),
        dcc.Interval(id="refresh", interval=1500, n_intervals=0),
    ],
)


# ── Main callback ─────────────────────────────────────────────────────────────
@app.callback(
    [Output("history",        "data"),
     Output("topology-graph", "elements"),
     Output("rate-chart",     "figure"),
     Output("stats-panel",    "children"),
     Output("alert-banner",   "children"),
     Output("phase-badge",    "children")],
    Input("refresh",          "n_intervals"),
    State("history",          "data"),
)
def update(_, history):
    try:
        topo    = requests.get(f"{CONTROLLER_URL}/topology", timeout=2).json()
        stats   = requests.get(f"{CONTROLLER_URL}/stats",    timeout=2).json()
        metrics = requests.get(f"{CONTROLLER_URL}/metrics",  timeout=2).json()
    except Exception:
        empty_fig = go.Figure().update_layout(
            plot_bgcolor="white", paper_bgcolor="white",
            xaxis={"visible": False}, yaxis={"visible": False},
            annotations=[{"text": "⚠️ Controller not reachable at :9000",
                           "showarrow": False, "font": {"size": 14}}],
        )
        return history, [], empty_fig, [], None, ""

    # ── Rebuild history entirely from server-side metrics (survives refresh) ──
    # Group entries by timestamp: {t: {src: packets}}
    by_t: dict = {}
    for entry in metrics[-MAX_PTS:]:
        t = entry["t"]
        by_t.setdefault(t, {})[entry["src"]] = entry["packets"]

    all_t     = sorted(by_t.keys())
    known_ips = {src for d in by_t.values() for src in d}
    rates: dict = {
        ip: [by_t[t].get(ip, 0) for t in all_t]
        for ip in known_ips
    }
    history = {"t": all_t, "rates": rates,
               "blocked": [], "t0": all_t[0] if all_t else None}

    blocked_ips = {n["ip"] for n in topo["nodes"] if n.get("status") == "blocked"}
    history["blocked"] = list(blocked_ips)

    # ── Topology elements ────────────────────────────────────────────────────
    elements = [
        {"data": {"id": "controller", "label": "Controller"},
         "classes": "controller", "position": POSITIONS["controller"]},
        {"data": {"id": "s1", "label": "OVS s1"},
         "classes": "switch", "position": POSITIONS["s1"]},
        {"data": {"source": "s1", "target": "controller"}, "classes": "infra"},
    ]
    for node in topo["nodes"]:
        if node["type"] == "switch":
            continue
        nid      = node["id"]
        ip       = node["ip"]
        is_block = node.get("status") == "blocked"
        cls      = "blocked" if is_block else ("h" + nid.lstrip("h"))
        label    = f"{nid}\n{ip.split('.')[-1]}"
        pos      = POSITIONS.get(nid, {"x": 265, "y": 350})
        elements.append({"data": {"id": ip, "label": label}, "classes": cls, "position": pos})
        elements.append({"data": {"source": ip, "target": "s1"}, "classes": "infra"})

    for edge in topo.get("edges", []):
        cls = "attack-edge" if edge["src"] in blocked_ips else "active-edge"
        elements.append({"data": {"source": edge["src"], "target": edge["dst"]}, "classes": cls})

    # ── Packet rate chart ────────────────────────────────────────────────────
    t_axis  = history["t"]
    n_pts   = len(t_axis)
    traces  = []
    for ip, rates in sorted(history["rates"].items()):
        padded = ([0] * max(0, n_pts - len(rates))) + rates[-n_pts:]
        color  = _COLORS.get(ip, "#888888")
        width  = 3 if ip in blocked_ips else 1.8
        label  = f"{ip.split('.')[-1]} ({ip})"
        if ip in blocked_ips:
            label += "  🔴 BLOCKED"
        elif ip == "10.0.0.5":
            label += "  🟠 victim"
        traces.append(go.Scatter(
            x=t_axis,
            y=[max(v, 1) for v in padded],  # log scale requires y > 0
            mode="lines", name=label,
            line={"color": color, "width": width},
        ))

    fig = go.Figure(data=traces)
    # Shade attack region
    if blocked_ips:
        for ip in blocked_ips:
            r = history["rates"].get(ip, [])
            for i, v in enumerate(r):
                if v > 1000 and i < len(t_axis):
                    fig.add_vrect(
                        x0=t_axis[i], x1=t_axis[-1],
                        fillcolor="#C44E52", opacity=0.06, line_width=0,
                        annotation_text="Attack phase",
                        annotation_position="top left",
                        annotation_font={"size": 11, "color": "#C44E52"},
                    )
                    break
    fig.update_layout(
        xaxis={"title": "Elapsed (s)", "gridcolor": "#EEE", "zerolinecolor": "#EEE"},
        yaxis={"title": "pkts / window", "type": "log",
               "gridcolor": "#EEE", "zerolinecolor": "#EEE"},
        legend={"orientation": "h", "y": -0.18, "font": {"size": 11}},
        plot_bgcolor="white", paper_bgcolor="white",
        margin={"l": 60, "r": 10, "t": 10, "b": 90},
        hovermode="x unified",
    )

    # ── Stats panel ──────────────────────────────────────────────────────────
    detect_n = stats["total_detections"]
    drop_n   = stats["drop_rules"]

    blocked_pills = [
        html.Span(ip, style={
            "background": "#FDECEA", "border": "1px solid #C44E52",
            "borderRadius": "4px", "padding": "3px 8px", "fontSize": "12px",
            "marginRight": "6px", "color": "#7A0000", "fontWeight": "bold",
        })
        for ip in sorted(blocked_ips)
    ] or [html.P("No blocked hosts", style={"color": "#888", "fontSize": "12px", "margin": "0"})]

    events = [
        html.P(ev["msg"], style={
            "fontSize": "11px", "margin": "3px 0",
            "color": "#C44E52" if "🚨" in ev["msg"] else "#444",
        })
        for ev in reversed(stats.get("recent_log", [])[-10:])
    ] or [html.P("—", style={"color": "#888", "fontSize": "12px"})]

    panel = [
        html.H4("System Status", style={"marginTop": "0", "color": "#1F4E79", "fontSize": "14px"}),
        html.Div([
            _card("Nodes",       stats["nodes"],      "#4C72B0"),
            _card("Flows",       stats["active_flows"], "#55A868"),
            _card("Detections",  detect_n,  "#C44E52" if detect_n else "#888"),
            _card("DROP Rules",  drop_n,    "#C44E52" if drop_n   else "#888"),
        ], style={"display": "flex", "flexWrap": "wrap"}),
        html.Hr(style={"margin": "12px 0"}),
        html.H4("Blocked IPs", style={"color": "#1F4E79", "fontSize": "13px", "margin": "0 0 6px"}),
        html.Div(blocked_pills),
        html.Hr(style={"margin": "12px 0"}),
        html.H4("Event Log", style={"color": "#1F4E79", "fontSize": "13px", "margin": "0 0 6px"}),
        html.Div(events),
    ]

    # ── Alert banner ─────────────────────────────────────────────────────────
    banner = html.Div(
        f"🚨  ATTACK DETECTED — Isolation Forest triggered DROP rules for: "
        f"{', '.join(sorted(blocked_ips))}",
        style={
            "background": "#C44E52", "color": "white",
            "padding": "10px 24px", "textAlign": "center",
            "fontWeight": "bold", "fontSize": "14px",
        },
    ) if blocked_ips else None

    # ── Phase badge ───────────────────────────────────────────────────────────
    if blocked_ips:
        badge = html.Span("⚠️  UNDER ATTACK", style={
            "background": "#C44E52", "color": "white",
            "padding": "5px 14px", "borderRadius": "16px", "fontSize": "13px",
        })
    elif stats["active_flows"] > 0:
        badge = html.Span("🟢  Normal Traffic", style={
            "background": "#55A868", "color": "white",
            "padding": "5px 14px", "borderRadius": "16px", "fontSize": "13px",
        })
    else:
        badge = html.Span("⏳  Waiting for traffic...", style={
            "background": "#888", "color": "white",
            "padding": "5px 14px", "borderRadius": "16px", "fontSize": "13px",
        })

    return history, elements, fig, panel, banner, badge


def _card(label, value, color):
    return html.Div([
        html.Div(str(value), style={"fontSize": "22px", "fontWeight": "bold", "color": color}),
        html.Div(label, style={"fontSize": "11px", "color": "#666"}),
    ], style={
        "textAlign": "center", "background": "#F8F9FA", "borderRadius": "6px",
        "padding": "8px 12px", "margin": "0 6px 6px 0", "minWidth": "58px",
    })


if __name__ == "__main__":
    print("Dashboard -> http://127.0.0.1:8050  (χρειάζεται ο controller στο :9000)")
    app.run(host="0.0.0.0", port=8050, debug=False)
