#!/usr/bin/env python3
"""
dashboard.py  (Management Plane — οπτικοποίηση σε πραγματικό χρόνο)
------------------------------------------------------------------
Web Dashboard με Dash + Cytoscape, σύμφωνα με την αρχιτεκτονική της
διπλωματικής. Οπτικοποιεί το Global Network View του controller ως γράφο
G=(V,E) και ανανεώνεται αυτόματα (callback functions), δείχνοντας οπτικά την
απόκριση του Defense Engine (οι κακόβουλοι κόμβοι γίνονται κόκκινοι/μπλοκάρονται).

Προϋπόθεση: να τρέχει ο controller (app_sdn/controller.py) στο :9000.

Εκτέλεση:
  python3 app_sdn/controller.py          # τερματικό 1
  python3 app_sdn/dashboard.py           # τερματικό 2 -> http://127.0.0.1:8050
  python3 app_sdn/simulate.py            # (ή τρέξε δική σου κίνηση)
"""

import os
import requests
import dash
from dash import dcc, html
from dash.dependencies import Input, Output
import dash_cytoscape as cyto

CONTROLLER_URL = os.environ.get("CONTROLLER_URL", "http://127.0.0.1:9000")

app = dash.Dash(__name__)
app.title = "SDN Defense Dashboard"

STYLESHEET = [
    {"selector": "node", "style": {
        "label": "data(label)", "font-size": "11px", "color": "#222",
        "text-valign": "center", "text-halign": "center",
        "width": 46, "height": 46, "background-color": "#4C72B0"}},
    {"selector": ".host", "style": {"background-color": "#4C72B0"}},
    {"selector": ".switch", "style": {"background-color": "#7F7F7F", "shape": "rectangle"}},
    {"selector": ".controller", "style": {"background-color": "#1F4E79", "shape": "diamond", "width": 60, "height": 60}},
    {"selector": ".blocked", "style": {"background-color": "#C44E52", "border-width": 3, "border-color": "#7A0000"}},
    {"selector": ".victim", "style": {"background-color": "#DD8452"}},
    {"selector": "edge", "style": {
        "curve-style": "bezier", "target-arrow-shape": "triangle",
        "line-color": "#BBBBBB", "target-arrow-color": "#BBBBBB", "width": 2}},
    {"selector": ".attack-edge", "style": {"line-color": "#C44E52", "target-arrow-color": "#C44E52", "width": 3}},
]

app.layout = html.Div(style={"fontFamily": "Arial", "margin": "0", "background": "#F7F9FC"}, children=[
    html.Div(style={"background": "#1F4E79", "color": "white", "padding": "14px 24px"}, children=[
        html.H2("SDN Defense Dashboard — Global Network View", style={"margin": "0"}),
        html.Span("Control + Data + Intelligence/Defense Plane (Isolation Forest)",
                  style={"fontSize": "13px", "opacity": "0.8"}),
    ]),
    html.Div(style={"display": "flex"}, children=[
        # γράφος τοπολογίας
        html.Div(style={"flex": "3", "padding": "12px"}, children=[
            cyto.Cytoscape(
                id="topology-graph",
                layout={"name": "cose", "animate": False},
                style={"width": "100%", "height": "560px", "background": "white",
                       "border": "1px solid #DDD", "borderRadius": "8px"},
                stylesheet=STYLESHEET,
                elements=[],
            ),
        ]),
        # πίνακας στατιστικών
        html.Div(style={"flex": "1", "padding": "12px"}, children=[
            html.Div(id="stats-panel", style={
                "background": "white", "border": "1px solid #DDD",
                "borderRadius": "8px", "padding": "16px", "minHeight": "560px"}),
        ]),
    ]),
    dcc.Interval(id="refresh", interval=1500, n_intervals=0),  # ανανέωση κάθε 1.5s
])


def node_class(node):
    t = node["type"]
    if node.get("status") == "blocked":
        return "blocked"
    if node["ip"] == "10.0.0.5":
        return "victim"
    return t


@app.callback(
    [Output("topology-graph", "elements"), Output("stats-panel", "children")],
    Input("refresh", "n_intervals"))
def update(_):
    try:
        topo = requests.get(f"{CONTROLLER_URL}/topology", timeout=2).json()
        stats = requests.get(f"{CONTROLLER_URL}/stats", timeout=2).json()
    except Exception:
        return [], [html.P("⚠️ Ο controller δεν είναι προσβάσιμος στο :9000")]

    elements = [{"data": {"id": "controller", "label": "Controller"}, "classes": "controller"}]
    blocked_ips = set()
    for node in topo["nodes"]:
        if node["type"] == "switch":
            continue
        cls = node_class(node)
        if cls == "blocked":
            blocked_ips.add(node["ip"])
        elements.append({"data": {"id": node["ip"], "label": node["ip"].split(".")[-1]},
                         "classes": cls})
    # ακμές = ενεργές ροές
    for e in topo["edges"]:
        ec = "attack-edge" if e["src"] in blocked_ips else ""
        elements.append({"data": {"source": e["src"], "target": e.get("dst", "controller")},
                         "classes": ec})

    panel = [
        html.H4("Κατάσταση Συστήματος", style={"marginTop": "0", "color": "#1F4E79"}),
        html.P([html.B("Κόμβοι: "), str(stats["nodes"])]),
        html.P([html.B("Ενεργές ροές: "), str(stats["active_flows"])]),
        html.P([html.B("Ανιχνεύσεις ανωμαλίας: "),
                html.Span(str(stats["total_detections"]), style={"color": "#C44E52", "fontWeight": "bold"})]),
        html.P([html.B("Ενεργοί κανόνες DROP: "), str(stats["drop_rules"])]),
        html.Hr(),
        html.H4("Ιστορικό", style={"color": "#1F4E79"}),
        html.Div([html.P(e["msg"], style={"fontSize": "12px", "margin": "4px 0"})
                  for e in reversed(stats.get("recent_log", []))]),
    ]
    return elements, panel


if __name__ == "__main__":
    print("Dashboard -> http://127.0.0.1:8050  (χρειάζεται ο controller στο :9000)")
    app.run(host="0.0.0.0", port=8050, debug=False)
