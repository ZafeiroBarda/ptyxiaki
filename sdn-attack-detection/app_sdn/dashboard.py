#!/usr/bin/env python3
"""
dashboard.py — SDN Defense Dashboard (Management Plane)
Real-time attack visualization for the diploma thesis demo.
No Cytoscape dependency — host status rendered as pure HTML cards.
"""

import io
import csv
import os

import dash
import plotly.graph_objects as go
import requests
from dash import Input, Output, State, dcc, html
from flask import Response

CONTROLLER_URL = os.environ.get("CONTROLLER_URL", "http://127.0.0.1:9000")
TIME_WINDOW = 120  # seconds of chart history

_COLORS = {
    "10.0.0.1": "#4C72B0",
    "10.0.0.2": "#55A868",
    "10.0.0.3": "#8172B2",
    "10.0.0.4": "#64B5CD",
    "10.0.0.5": "#DD8452",
    "10.0.0.6": "#C44E52",
}

_HOSTS = [
    {"id": "h1", "ip": "10.0.0.1"},
    {"id": "h2", "ip": "10.0.0.2"},
    {"id": "h3", "ip": "10.0.0.3"},
    {"id": "h4", "ip": "10.0.0.4"},
    {"id": "h5", "ip": "10.0.0.5"},
    {"id": "h6", "ip": "10.0.0.6"},
]

_ATTACK_TYPES = [
    {"label": "SYN Flood",  "value": "syn",  "cmd": "--syn  --flood -p 80"},
    {"label": "UDP Flood",  "value": "udp",  "cmd": "--udp  --flood -p 53"},
    {"label": "ICMP Flood", "value": "icmp", "cmd": "--icmp --flood"},
]

app = dash.Dash(__name__)
app.title = "SDN Defense Dashboard"

# ── Ζώνες αρχιτεκτονικής SDN (planes) ─────────────────────────────────────────
# Κάθε τμήμα του dashboard αντιστοιχεί σε ΕΝΑ επίπεδο της αρχιτεκτονικής SDN,
# ώστε η δομή να διαβάζεται άμεσα, όπως στο κλασικό διάγραμμα SDN:
#   Management (πάνω)  →  Control & Defense (μέση)  →  Data (κάτω).
_PLANE = {
    "mgmt": {
        "name": "MANAGEMENT PLANE",
        "tech": "Dash / Plotly · Κονσόλα χειριστή & οπτικοποίηση",
        "color": "#1F4E79", "icon": "🖥️",
    },
    "control": {
        "name": "CONTROL & DEFENSE PLANE",
        "tech": "Flask Controller · Isolation Forest (Intelligence/Defense) · Flow Table",
        "color": "#6A4C93", "icon": "🧠",
    },
    "data": {
        "name": "DATA PLANE",
        "tech": "Mininet + Open vSwitch · Hosts, ροές & προώθηση πακέτων",
        "color": "#1B7A3D", "icon": "🔀",
    },
}


def _plane_header(key):
    """Χρωματιστή επικεφαλίδα ζώνης με το όνομα του plane και την τεχνολογία του."""
    p = _PLANE[key]
    return html.Div(
        style={"display": "flex", "alignItems": "center", "gap": "10px",
               "background": p["color"], "color": "white", "padding": "7px 16px",
               "borderRadius": "8px 8px 0 0"},
        children=[
            html.Span(p["icon"], style={"fontSize": "17px"}),
            html.Span(p["name"], style={"fontWeight": "bold", "fontSize": "13px",
                                        "letterSpacing": "1.5px"}),
            html.Span(p["tech"], style={"fontSize": "11px", "opacity": "0.85"}),
        ],
    )


def _plane_band(key, body_children, body_style=None):
    """Πλήρης ζώνη: επικεφαλίδα plane + λευκό σώμα με το περιεχόμενο."""
    inner = {"background": "white", "border": "1px solid #DDD", "borderTop": "none",
             "borderRadius": "0 0 8px 8px", "padding": "12px"}
    if body_style:
        inner.update(body_style)
    return html.Div(style={"padding": "0 10px"}, children=[
        _plane_header(key),
        html.Div(style=inner, children=body_children),
    ])


def _plane_connector(up_label, down_label):
    """Δείχνει τη ροή δεδομένων ανάμεσα σε δύο γειτονικές ζώνες (southbound/northbound)."""
    return html.Div(
        style={"display": "flex", "justifyContent": "center", "gap": "36px",
               "padding": "4px 0", "fontSize": "11px", "color": "#5A5A5A",
               "fontFamily": "monospace", "flexWrap": "wrap"},
        children=[
            html.Span(f"▲  {up_label}"),
            html.Span(f"{down_label}  ▼"),
        ],
    )

app.layout = html.Div(
    style={"fontFamily": "'Segoe UI', Arial, sans-serif", "margin": "0",
           "background": "#F0F4F8", "paddingBottom": "16px"},
    children=[

        # ── Τίτλος εφαρμογής ──────────────────────────────────────────────────
        html.Div(
            style={"background": "#12325A", "color": "white", "padding": "12px 24px",
                   "display": "flex", "justifyContent": "space-between", "alignItems": "center"},
            children=[
                html.Div([
                    html.H2("SDN Defense Dashboard",
                            style={"margin": "0", "fontSize": "20px"}),
                    html.Span("Αρχιτεκτονική τριών επιπέδων "
                              "(Management · Control/Defense · Data) — "
                              "Real-time ανίχνευση ανωμαλιών με Isolation Forest",
                              style={"fontSize": "12px", "opacity": "0.85"}),
                ]),
                html.Div(id="phase-badge"),
            ],
        ),

        # ── Attack alert banner ───────────────────────────────────────────────
        html.Div(id="alert-banner"),

        # ══════════════════ MANAGEMENT PLANE (πάνω) ═══════════════════════════
        _plane_band("mgmt",
            body_style={"display": "flex", "alignItems": "center",
                        "gap": "18px", "flexWrap": "wrap"},
            body_children=[
                html.Span("🎮 Demo Control",
                          style={"fontWeight": "bold", "color": "#1F4E79",
                                 "fontSize": "13px", "whiteSpace": "nowrap"}),
                html.Div([
                    html.Label("Victim", style={"fontSize": "11px", "color": "#666",
                                                "display": "block", "marginBottom": "3px"}),
                    dcc.Dropdown(
                        id="victim-select",
                        options=[{"label": f"{h['id']} ({h['ip']})", "value": h["id"]}
                                 for h in _HOSTS],
                        value="h5", clearable=False,
                        style={"width": "160px", "fontSize": "12px"},
                    ),
                ]),
                html.Div([
                    html.Label("Attacker(s)", style={"fontSize": "11px", "color": "#666",
                                                     "display": "block", "marginBottom": "3px"}),
                    dcc.Dropdown(
                        id="attacker-select",
                        options=[{"label": f"{h['id']} ({h['ip']})", "value": h["id"]}
                                 for h in _HOSTS],
                        value=["h6"], multi=True, clearable=False,
                        style={"width": "260px", "fontSize": "12px"},
                    ),
                ]),
                html.Div([
                    html.Label("Attack Type", style={"fontSize": "11px", "color": "#666",
                                                     "display": "block", "marginBottom": "3px"}),
                    dcc.Dropdown(
                        id="attack-type-select",
                        options=[{"label": a["label"], "value": a["value"]}
                                 for a in _ATTACK_TYPES],
                        value="syn", clearable=False,
                        style={"width": "150px", "fontSize": "12px"},
                    ),
                ]),
                html.Button("🚀 Start Attack", id="btn-start", n_clicks=0, style={
                    "background": "#C44E52", "color": "white", "border": "none",
                    "padding": "8px 18px", "borderRadius": "6px", "cursor": "pointer",
                    "fontWeight": "bold", "fontSize": "13px",
                }),
                html.Button("🛑 Stop Attack", id="btn-stop", n_clicks=0, style={
                    "background": "#555", "color": "white", "border": "none",
                    "padding": "8px 18px", "borderRadius": "6px", "cursor": "pointer",
                    "fontSize": "13px",
                }),
                html.Div(id="sim-status", style={"fontSize": "12px", "color": "#555"}),
                html.Div(style={"flex": "1"}),  # spacer σπρώχνει τα export δεξιά
                html.A("⬇ Export CSV", href="/export/flows.csv",
                       style={"display": "inline-block", "background": "#4C72B0",
                              "color": "white", "padding": "6px 14px",
                              "borderRadius": "6px", "fontSize": "12px",
                              "textDecoration": "none", "marginRight": "6px"}),
                html.A("⬇ Blocked History", href="/export/blocked.csv",
                       style={"display": "inline-block", "background": "#888",
                              "color": "white", "padding": "6px 14px",
                              "borderRadius": "6px", "fontSize": "12px",
                              "textDecoration": "none"}),
            ],
        ),

        _plane_connector(
            "κατάσταση / μετρικές: GET /stats · /metrics · /flow_table (poll 1s)",
            "εντολές χειριστή: POST /simulate/command",
        ),

        # ══════════════════ CONTROL & DEFENSE PLANE (μέση) ════════════════════
        _plane_band("control",
            body_style={"display": "flex", "gap": "12px", "alignItems": "flex-start",
                        "flexWrap": "wrap"},
            body_children=[
                html.Div(style={"flex": "2", "minWidth": "300px"}, children=[
                    html.Div(id="stats-panel"),
                ]),
                html.Div(style={"flex": "1", "minWidth": "220px",
                                "borderLeft": "1px solid #EEE", "paddingLeft": "12px"},
                         children=[
                             html.H4("Anomaly Scores — Isolation Forest f(x)",
                                     style={"color": "#6A4C93", "fontSize": "13px",
                                            "margin": "0 0 8px"}),
                             html.Div(id="anomaly-panel"),
                         ]),
            ],
        ),

        _plane_connector(
            "τηλεμετρία ροών: POST /telemetry  (packets · bytes · duration ανά πηγή IP)",
            "αντιμετώπιση: εγκατάσταση κανόνων DROP στο Flow Table",
        ),

        # ══════════════════ DATA PLANE (κάτω) ═════════════════════════════════
        _plane_band("data",
            body_style={"display": "flex", "gap": "12px", "alignItems": "flex-start",
                        "flexWrap": "wrap"},
            body_children=[
                html.Div(style={"flex": "2", "minWidth": "280px"}, children=[
                    html.H4("Network Hosts (h1–h6) & Switch",
                            style={"margin": "0 0 10px", "color": "#1B7A3D",
                                   "fontSize": "13px"}),
                    html.Div(id="host-panel"),
                ]),
                html.Div(style={"flex": "3", "minWidth": "320px"}, children=[
                    html.H4("Packet Rate per Host  (pkts / window, log scale)",
                            style={"margin": "0 0 6px", "color": "#1B7A3D",
                                   "fontSize": "13px"}),
                    dcc.Graph(id="rate-chart", style={"height": "460px"},
                              config={"displayModeBar": False}),
                ]),
            ],
        ),

        dcc.Store(id="history", data={"t": [], "rates": {}, "blocked": [], "t0": None}),
        dcc.Interval(id="refresh", interval=1000, n_intervals=0),
    ],
)


# ── Callback ──────────────────────────────────────────────────────────────────
@app.callback(
    [Output("history",       "data"),
     Output("host-panel",    "children"),
     Output("rate-chart",    "figure"),
     Output("stats-panel",   "children"),
     Output("alert-banner",  "children"),
     Output("phase-badge",   "children"),
     Output("anomaly-panel", "children")],
    Input("refresh",         "n_intervals"),
    [State("history",        "data"),
     State("victim-select",  "value"),
     State("attacker-select","value")],
)
def update(_, history, selected_victim, selected_attackers):
    _default_stats = {"nodes": 0, "active_flows": 0, "drop_rules": 0,
                      "total_detections": 0, "recent_log": []}
    stats   = _default_stats.copy()
    metrics = []
    ft      = {}
    anomaly_scores = {}

    for url, key in [
        (f"{CONTROLLER_URL}/stats",          "stats"),
        (f"{CONTROLLER_URL}/metrics",        "metrics"),
        (f"{CONTROLLER_URL}/flow_table",     "ft"),
        (f"{CONTROLLER_URL}/anomaly_scores", "scores"),
    ]:
        try:
            data = requests.get(url, timeout=2).json()
            if key == "stats":     stats   = data
            elif key == "metrics": metrics = data
            elif key == "scores":  anomaly_scores = data
            elif key == "ft":      ft      = data
        except Exception:
            pass

    # ── Rebuild rolling history ───────────────────────────────────────────────
    by_t: dict = {}
    if metrics:
        latest_t = max(e["t"] for e in metrics)
        cutoff_t = latest_t - TIME_WINDOW
        for entry in metrics:
            if entry["t"] >= cutoff_t:
                t = entry["t"]
                by_t.setdefault(t, {})[entry["src"]] = entry["packets"]

    all_t     = sorted(by_t.keys())
    known_ips = {src for d in by_t.values() for src in d}
    rates_map = {ip: [by_t[t].get(ip, 0) for t in all_t] for ip in known_ips}
    history   = {"t": all_t, "rates": rates_map, "blocked": [], "t0": all_t[0] if all_t else None}

    blocked_ips = set(ft.keys()) if ft else set()
    history["blocked"] = list(blocked_ips)

    # ── Host Status Panel ─────────────────────────────────────────────────────
    recent_rate: dict = {}
    if metrics:
        cutoff = max(e["t"] for e in metrics) - 10
        for e in metrics:
            if e["t"] >= cutoff:
                recent_rate[e["src"]] = max(recent_rate.get(e["src"], 0), e["packets"])

    _victim_id    = selected_victim    or "h5"
    _attacker_ids = selected_attackers or []

    cards = []
    for h in _HOSTS:
        ip   = h["ip"]
        hid  = h["id"]
        rate = recent_rate.get(ip, 0)
        is_blocked = ip in blocked_ips

        # Dynamic role based on demo control selection
        if hid == _victim_id:
            role = "Victim"
        elif hid in _attacker_ids:
            role = "Attacker"
        else:
            role = "Legitimate"

        if is_blocked:
            icon, label, txt_color, bg, border = "🔴", "BLOCKED",   "#C44E52", "#FDECEA", "2px solid #C44E52"
        elif role == "Victim":
            icon, label, txt_color, bg, border = "🟠", "Victim",     "#DD8452", "#FFF3E8", "1px solid #DD8452"
        elif role == "Attacker":
            icon, label, txt_color, bg, border = "⚡", "Attacker",   "#9B59B6", "#F8F0FF", "1px solid #C39BD3"
        elif rate > 0:
            icon, label, txt_color, bg, border = "🟢", "Active",     "#55A868", "#F0FFF4", "1px solid #C8E6C9"
        else:
            icon, label, txt_color, bg, border = "⚪", "Idle",       "#888",    "#F8F9FA", "1px solid #DDD"

        cards.append(html.Div(
            style={"display": "flex", "alignItems": "center", "gap": "10px",
                   "padding": "8px 12px", "marginBottom": "6px",
                   "borderRadius": "8px", "background": bg, "border": border},
            children=[
                html.Div(h["id"].upper(), style={
                    "width": "36px", "height": "36px", "borderRadius": "50%",
                    "background": _COLORS.get(ip, "#888"),
                    "display": "flex", "alignItems": "center", "justifyContent": "center",
                    "color": "white", "fontWeight": "bold", "fontSize": "13px", "flexShrink": "0",
                }),
                html.Div(style={"flex": "1"}, children=[
                    html.Div(style={"display": "flex", "justifyContent": "space-between"}, children=[
                        html.Span(ip, style={"fontWeight": "bold", "fontSize": "13px",
                                             "fontFamily": "monospace"}),
                        html.Span(f"{icon} {label}", style={"fontSize": "11px",
                                                             "color": txt_color, "fontWeight": "bold"}),
                    ]),
                    html.Div(style={"display": "flex", "justifyContent": "space-between",
                                    "marginTop": "2px"}, children=[
                        html.Span(role, style={"fontSize": "11px", "color": "#666"}),
                        html.Span(f"{rate:,} pkts" if rate else "—",
                                  style={"fontSize": "11px", "color": "#444", "fontFamily": "monospace"}),
                    ]),
                ]),
            ],
        ))

    # Infra row: switch + controller
    cards.append(html.Div(
        style={"display": "flex", "gap": "6px", "marginTop": "12px",
               "paddingTop": "10px", "borderTop": "1px solid #EEE"},
        children=[
            html.Div(style={"flex": "1", "textAlign": "center", "background": "#F0F4F8",
                            "borderRadius": "6px", "padding": "8px 4px", "fontSize": "11px"},
                     children=[
                         html.Div("🔲", style={"fontSize": "20px"}),
                         html.Div("OVS s1", style={"fontWeight": "bold", "color": "#555"}),
                         html.Div("Switch", style={"color": "#888"}),
                     ]),
            html.Div(style={"flex": "1", "textAlign": "center", "background": "#EDF2F7",
                            "borderRadius": "6px", "padding": "8px 4px", "fontSize": "11px"},
                     children=[
                         html.Div("🧠", style={"fontSize": "20px"}),
                         html.Div("Controller", style={"fontWeight": "bold", "color": "#1F4E79"}),
                         html.Div("Isolation Forest", style={"color": "#888"}),
                     ]),
        ],
    ))

    host_panel = html.Div(cards)

    # ── Packet Rate Chart ─────────────────────────────────────────────────────
    t_axis = history["t"]
    n_pts  = len(t_axis)
    traces = []
    for ip, r in sorted(history["rates"].items()):
        padded = ([0] * max(0, n_pts - len(r))) + r[-n_pts:]
        color  = _COLORS.get(ip, "#888888")
        width  = 3 if ip in blocked_ips else 1.8
        lbl    = f"{ip.split('.')[-1]} ({ip})"
        if ip in blocked_ips:
            lbl += "  🔴 BLOCKED"
        elif ip == "10.0.0.5":
            lbl += "  🟠 victim"
        traces.append(go.Scatter(
            x=t_axis, y=[max(v, 1) for v in padded],
            mode="lines", name=lbl,
            line={"color": color, "width": width, "shape": "spline", "smoothing": 0.8},
        ))

    fig = go.Figure(data=traces)
    if blocked_ips:
        for ip in blocked_ips:
            r = history["rates"].get(ip, [])
            for i, v in enumerate(r):
                if v > 1000 and i < len(t_axis):
                    fig.add_vrect(
                        x0=t_axis[i], x1=t_axis[-1],
                        fillcolor="#C44E52", opacity=0.06, line_width=0,
                        annotation_text="Attack phase", annotation_position="top left",
                        annotation_font={"size": 11, "color": "#C44E52"},
                    )
                    break

    x_end   = all_t[-1] if all_t else TIME_WINDOW
    x_start = x_end - TIME_WINDOW
    fig.update_layout(
        xaxis={"title": "Elapsed (s)", "gridcolor": "#EEE", "zerolinecolor": "#EEE",
               "range": [x_start, x_end + 2]},
        yaxis={"title": "pkts / window", "type": "log",
               "gridcolor": "#EEE", "zerolinecolor": "#EEE"},
        legend={"orientation": "h", "y": -0.18, "font": {"size": 11}},
        plot_bgcolor="white", paper_bgcolor="white",
        margin={"l": 60, "r": 10, "t": 10, "b": 90},
        hovermode="x unified",
        uirevision="demo",
        transition={"duration": 400, "easing": "cubic-in-out"},
    )

    # ── Stats Panel ───────────────────────────────────────────────────────────
    detect_n = stats.get("total_detections", 0)
    drop_n   = len(blocked_ips)  # derive from flow_table (authoritative, already expire()'d)

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
            _card("Nodes",      stats.get("nodes", 0),        "#4C72B0"),
            _card("Flows",      stats.get("active_flows", 0), "#55A868"),
            _card("Detections", detect_n, "#C44E52" if detect_n else "#888"),
            _card("DROP Rules", drop_n,   "#C44E52" if drop_n   else "#888"),
        ], style={"display": "flex", "flexWrap": "wrap"}),
        html.Hr(style={"margin": "12px 0"}),
        html.H4("Blocked IPs", style={"color": "#1F4E79", "fontSize": "13px", "margin": "0 0 6px"}),
        html.Div(blocked_pills),
        html.Hr(style={"margin": "12px 0"}),
        html.H4("Event Log", style={"color": "#1F4E79", "fontSize": "13px", "margin": "0 0 6px"}),
        html.Div(events),
    ]

    # ── Banner + Badge ────────────────────────────────────────────────────────
    under_attack = bool(blocked_ips) or drop_n > 0
    banner_ips   = sorted(blocked_ips) if blocked_ips else ["(see flow table)"]
    banner = html.Div(
        f"🚨  ATTACK DETECTED — Isolation Forest triggered DROP rules for: {', '.join(banner_ips)}",
        style={
            "background": "#C44E52", "color": "white",
            "padding": "10px 24px", "textAlign": "center",
            "fontWeight": "bold", "fontSize": "14px",
        },
    ) if under_attack else None

    if under_attack:
        badge = html.Span("⚠️  UNDER ATTACK", style={
            "background": "#C44E52", "color": "white",
            "padding": "5px 14px", "borderRadius": "16px", "fontSize": "13px",
        })
    elif stats.get("active_flows", 0) > 0:
        badge = html.Span("🟢  Normal Traffic", style={
            "background": "#55A868", "color": "white",
            "padding": "5px 14px", "borderRadius": "16px", "fontSize": "13px",
        })
    else:
        badge = html.Span("⏳  Waiting for traffic...", style={
            "background": "#888", "color": "white",
            "padding": "5px 14px", "borderRadius": "16px", "fontSize": "13px",
        })

    # ── Anomaly Scores Panel ──────────────────────────────────────────────────
    # IF score: more negative = more anomalous. Threshold ≈ 0.
    # Normalize to 0-100% "threat level" for display: score=-0.5 → 100%, score=+0.2 → 0%
    def _threat_pct(score):
        # clamp to [-0.5, 0.2] range then normalize
        clamped = max(-0.5, min(0.2, score))
        return round((0.2 - clamped) / 0.7 * 100)

    score_rows = []
    for h in _HOSTS:
        ip = h["ip"]
        sc = anomaly_scores.get(ip)
        if sc is None:
            continue
        pct   = _threat_pct(sc)
        color = "#C44E52" if pct > 70 else ("#DD8452" if pct > 40 else "#55A868")
        score_rows.append(html.Div(style={"marginBottom": "5px"}, children=[
            html.Div(style={"display": "flex", "justifyContent": "space-between",
                            "fontSize": "11px", "marginBottom": "2px"}, children=[
                html.Span(f"{h['id']} ({ip})", style={"color": "#444"}),
                html.Span(f"{pct}%", style={"color": color, "fontWeight": "bold"}),
            ]),
            html.Div(style={"height": "6px", "borderRadius": "3px",
                            "background": "#EEE", "overflow": "hidden"}, children=[
                html.Div(style={"height": "100%", "width": f"{pct}%",
                                "background": color, "borderRadius": "3px",
                                "transition": "width 0.5s ease"}),
            ]),
        ]))
    anomaly_panel = html.Div(score_rows) if score_rows else \
        html.P("No scores yet", style={"color": "#888", "fontSize": "11px"})

    return history, host_panel, fig, panel, banner, badge, anomaly_panel


@app.callback(
    Output("sim-status", "children"),
    [Input("btn-start", "n_clicks"), Input("btn-stop", "n_clicks")],
    [State("victim-select", "value"), State("attacker-select", "value"),
     State("attack-type-select", "value")],
    prevent_initial_call=True,
)
def handle_sim(start_clicks, stop_clicks, victim, attackers, attack_type):
    triggered = dash.callback_context.triggered[0]["prop_id"].split(".")[0]
    if triggered == "btn-start":
        if not attackers:
            return "⚠️ Επέλεξε τουλάχιστον έναν attacker"
        if victim in (attackers or []):
            return "⚠️ Victim και attacker δεν μπορούν να είναι ο ίδιος host"
        label = next((a["label"] for a in _ATTACK_TYPES if a["value"] == attack_type), attack_type)
        try:
            requests.post(f"{CONTROLLER_URL}/simulate/command",
                          json={"cmd": "start", "attackers": attackers,
                                "victim": victim, "attack_type": attack_type},
                          timeout=2)
            return f"✅ {label}: {', '.join(attackers)} → {victim}"
        except Exception:
            return "❌ Controller μη διαθέσιμος"
    elif triggered == "btn-stop":
        try:
            requests.post(f"{CONTROLLER_URL}/simulate/command",
                          json={"cmd": "stop"}, timeout=2)
            return "🛑 Επίθεση σταμάτησε"
        except Exception:
            return "❌ Controller μη διαθέσιμος"
    return ""


def _card(label, value, color):
    return html.Div([
        html.Div(str(value), style={"fontSize": "22px", "fontWeight": "bold", "color": color}),
        html.Div(label, style={"fontSize": "11px", "color": "#666"}),
    ], style={
        "textAlign": "center", "background": "#F8F9FA", "borderRadius": "6px",
        "padding": "8px 12px", "margin": "0 6px 6px 0", "minWidth": "58px",
    })


@app.server.route("/export/flows.csv")
def export_flows():
    """Download live flow metrics from controller as CSV."""
    try:
        metrics = requests.get(f"{CONTROLLER_URL}/metrics", timeout=3).json()
        ft      = requests.get(f"{CONTROLLER_URL}/flow_table", timeout=3).json()
    except Exception:
        metrics, ft = [], {}

    buf = io.StringIO()
    w   = csv.writer(buf)
    w.writerow(["t", "src_ip", "packets", "bytes", "blocked"])
    for e in metrics:
        w.writerow([e.get("t"), e.get("src"), e.get("packets"),
                    e.get("bytes"), e.get("src") in ft])
    buf.seek(0)
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=flows.csv"})


@app.server.route("/export/blocked.csv")
def export_blocked():
    """Download blocked IP history from controller as CSV."""
    try:
        ft = requests.get(f"{CONTROLLER_URL}/flow_table", timeout=3).json()
    except Exception:
        ft = {}

    buf = io.StringIO()
    w   = csv.writer(buf)
    w.writerow(["ip", "action", "priority", "expires_in"])
    for ip, rule in ft.items():
        w.writerow([ip, rule.get("action"), rule.get("priority"),
                    rule.get("expires_in")])
    buf.seek(0)
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=blocked.csv"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8050, debug=False)
