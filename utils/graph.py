import json
import math
import tempfile
import os
from typing import Dict, List, Optional, Set
from collections import defaultdict
import networkx as nx
import plotly.graph_objects as go
from pyvis.network import Network
import re
import html


# ═══════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════

COLORS = {
    "source":         {"bg": "#3B82F6", "border": "#1D4ED8", "highlight": "#60A5FA"},
    "cte":            {"bg": "#10B981", "border": "#047857", "highlight": "#34D399"},
    "terminal":       {"bg": "#F59E0B", "border": "#B45309", "highlight": "#FCD34D"},
    "matched":        {"bg": "#F59E0B", "border": "#B45309", "highlight": "#FCD34D"},
    "dimmed":         {"bg": "#E2E8F0", "border": "#CBD5E1", "highlight": "#F1F5F9"},
    "edge":           "#94A3B8",
    "edge_highlight": "#475569",
    "edge_hot":       "#F59E0B",
    "background":     "#F8FAFC",
    "font":           "#1E293B",
}

PHYSICS_PRESETS = {
    "hierarchical": {
        "enabled": True,
        "levelSeparation": 180,
        "nodeSpacing": 120,
        "treeSpacing": 200,
        "direction": "LR",
        "sortMethod": "directed",
        "shakeTowards": "roots",
    },
    "barnes_hut": {
        "gravitationalConstant": -8000,
        "centralGravity": 0.3,
        "springLength": 140,
        "springConstant": 0.04,
        "damping": 0.09,
        "avoidOverlap": 0.8,
    },
}


def extract_joins(sql):
    joins = re.findall(r"(join\s+.*?\s+on\s+.*?)(?:\n|$)", sql, re.IGNORECASE)
    return joins

def detect_duplicate_risk(sql):
    sql_lower = sql.lower()

    if "cross join" in sql_lower:
        return "🚨 CROSS JOIN (high duplication risk)"

    if "join" in sql_lower and "group by" not in sql_lower:
        return "⚠️ JOIN without aggregation"

    if "join" in sql_lower and "distinct" not in sql_lower:
        return "⚠️ No DISTINCT after JOIN"

    return ""

def highlight_column(sql, column):
    if not column:
        return sql

    pattern = re.compile(rf"\\b({re.escape(column)})\\b", re.IGNORECASE)
    return pattern.sub(r"<mark>\\1</mark>", sql)
# ═══════════════════════════════════════════════════════════════
# CORE GRAPH BUILDER
# ═══════════════════════════════════════════════════════════════

def create_graph(dependencies: Dict[str, List[str]]) -> nx.DiGraph:
    """
    Build a directed graph from a dependency dict.
    {"b": ["a"]}  =>  a → b
    """
    G = nx.DiGraph()
    for node, deps in dependencies.items():
        G.add_node(node)
        for dep in deps:
            G.add_edge(dep, node)
    return G


# ═══════════════════════════════════════════════════════════════
# SHARED HELPERS
# ═══════════════════════════════════════════════════════════════
def build_cte_tooltip(node, G, kind, cte_sql_map=None, search_column=None):
    base = _build_hover_title(node, G, kind)

    if not cte_sql_map:
        return base

    sql = cte_sql_map.get(node)
    if not sql:
        return base

    # Highlight searched column
    if search_column:
        sql = highlight_column(sql, search_column)

    escaped_sql = html.escape(sql)

    return f"""
    {base}
    <br><br>
    <b>SQL:</b><br>
    <pre style="
        max-width:600px;
        white-space:pre-wrap;
        font-size:11px;
        background:#0f172a;
        color:#e2e8f0;
        padding:10px;
        border-radius:6px;
    ">{escaped_sql}</pre>

    <button onclick="navigator.clipboard.writeText(`{sql}`)"
        style="
            margin-top:6px;
            padding:4px 8px;
            font-size:11px;
            background:#2563eb;
            color:white;
            border:none;
            border-radius:4px;
            cursor:pointer;
        ">
        📋 Copy SQL
    </button>
    """
def _classify_node(node: str, G: nx.DiGraph, dependent_nodes: set) -> str:
    if node not in dependent_nodes:
        return "source"
    if G.out_degree(node) == 0:
        return "terminal"
    return "cte"


def _node_size(node: str, G: nx.DiGraph, base: int = 22) -> int:
    degree = G.in_degree(node) + G.out_degree(node)
    return max(base, min(50, base + degree * 3))


def _build_hover_title(node: str, G: nx.DiGraph, kind: str) -> str:
    preds = list(G.predecessors(node))
    succs = list(G.successors(node))
    kind_label = {"source": "Base Table", "cte": "CTE", "terminal": "Terminal CTE"}[kind]
    return "<br>".join([
        f"<b>{node}</b>",
        f"<i>{kind_label}</i>",
        f"Depends on ({len(preds)}): {', '.join(preds) if preds else '—'}",
        f"Used by  ({len(succs)}): {', '.join(succs) if succs else '—'}",
    ])


def _graph_metrics(G: nx.DiGraph) -> Dict:
    try:
        longest = nx.dag_longest_path_length(G)
    except nx.NetworkXUnfeasible:
        longest = -1
    return {
        "nodes":      G.number_of_nodes(),
        "edges":      G.number_of_edges(),
        "depth":      longest,
        "has_cycles": not nx.is_directed_acyclic_graph(G),
        "components": nx.number_weakly_connected_components(G),
    }


def _hierarchical_layout(G: nx.DiGraph, x_spacing: float = 3.0, y_spacing: float = 2.0):
    layers: Dict[str, int] = {}
    for node in nx.topological_sort(G):
        preds = list(G.predecessors(node))
        layers[node] = max((layers[p] for p in preds), default=-1) + 1

    layer_groups: Dict[int, List[str]] = defaultdict(list)
    for node, layer in layers.items():
        layer_groups[layer].append(node)

    pos = {}
    for layer, nodes in layer_groups.items():
        count = len(nodes)
        for i, node in enumerate(sorted(nodes)):
            y = (i - (count - 1) / 2.0) * y_spacing
            pos[node] = (layer * x_spacing, y)
    return pos


# ═══════════════════════════════════════════════════════════════
# STATIC GRAPH — PLOTLY
# ═══════════════════════════════════════════════════════════════

def draw_dependency_graph(
    dependencies: Dict[str, List[str]],
    highlight_nodes: Set[str] = None,
    matched_nodes: Set[str] = None,
    duplicate_nodes: Set[str] = None,
) -> go.Figure:
    """
    Interactive Plotly dependency graph.
    When highlight_nodes / matched_nodes / duplicate_nodes are provided:
      🟡 matched_nodes or duplicate_nodes  = direct column match / duplicate risk
      🔵/🟢 highlight_nodes = ancestors/descendants (normal colour)
      🩶 everything else  = dimmed grey
    """
    highlight_nodes = highlight_nodes or set()
    matched_nodes   = matched_nodes   or set()
    duplicate_nodes = duplicate_nodes or set()

    G = create_graph(dependencies)

    if len(G.nodes) == 0:
        fig = go.Figure()
        fig.add_annotation(text="No dependencies to display",
                           x=0.5, y=0.5, showarrow=False, font_size=16)
        fig.update_layout(xaxis_visible=False, yaxis_visible=False)
        return fig

    try:
        pos = _hierarchical_layout(G)
    except nx.NetworkXUnfeasible:
        pos = nx.spring_layout(G, k=2.5, iterations=80, seed=42)

    dependent_nodes = set(dependencies.keys())
    all_nodes       = set(G.nodes())
    source_nodes    = all_nodes - dependent_nodes
    in_deg          = dict(G.in_degree())
    out_deg         = dict(G.out_degree())
    searching       = bool(highlight_nodes or matched_nodes or duplicate_nodes)

    def node_color(n):
        if n in matched_nodes or n in duplicate_nodes:
            return "#F59E0B"
        if not searching or n in highlight_nodes:
            return "#3B82F6" if n in source_nodes else "#10B981"
        return "#CBD5E1"  # dimmed

    def node_opacity(n):
        if not searching or n in highlight_nodes or n in matched_nodes or n in duplicate_nodes:
            return 1.0
        return 0.25

    def edge_style(u, v):
        in_sub = u in highlight_nodes and v in highlight_nodes
        is_hot = (
            u in matched_nodes or v in matched_nodes
            or u in duplicate_nodes or v in duplicate_nodes
        )
        if not searching:
            return "#94A3B8", 1.2
        if in_sub and is_hot:
            return "#F59E0B", 2.5
        if in_sub:
            return "#64748B", 2.0
        return "#E2E8F0", 0.6

    # ── Edge traces ──────────────────────────────────────────
    edge_traces = []
    annotations = []
    for u, v in G.edges():
        x0, y0 = pos[u]
        x1, y1 = pos[v]
        color, width = edge_style(u, v)

        edge_traces.append(go.Scatter(
            x=[x0, x1, None], y=[y0, y1, None],
            mode="lines",
            line=dict(width=width, color=color),
            hoverinfo="none", showlegend=False,
        ))

        dx, dy = x1 - x0, y1 - y0
        dist   = math.hypot(dx, dy) or 1
        shrink = 0.18
        annotations.append(dict(
            x=x1 - dx * shrink, y=y1 - dy * shrink,
            ax=x0, ay=y0,
            xref="x", yref="y", axref="x", ayref="y",
            showarrow=True, arrowhead=2, arrowsize=1.2,
            arrowwidth=1.5, arrowcolor=color,
        ))

    # ── Node traces ──────────────────────────────────────────
    def make_trace(node_list, name, symbol):
        if not node_list:
            return None
        colors   = [node_color(n) for n in node_list]
        opacities = [node_opacity(n) for n in node_list]
        sizes    = [max(20, min(50, 20 + (in_deg[n] + out_deg[n]) * 3)) for n in node_list]
        return go.Scatter(
            x=[pos[n][0] for n in node_list],
            y=[pos[n][1] for n in node_list],
            mode="markers+text",
            marker=dict(
                symbol=symbol, size=sizes, color=colors,
                opacity=opacities,
                line=dict(width=2, color="#475569"),
            ),
            text=node_list,
            textposition="top center",
            textfont=dict(size=10, color="#1E293B"),
            hovertemplate=(
                "<b>%{customdata[0]}</b><br>"
                "In: %{customdata[1]}  Out: %{customdata[2]}<extra></extra>"
            ),
            customdata=[[n, in_deg[n], out_deg[n]] for n in node_list],
            name=name, showlegend=True,
        )

    traces = [t for t in [
        *edge_traces,
        make_trace(list(source_nodes),    "Base tables",   "circle"),
        make_trace(list(dependent_nodes), "CTEs / Derived","square"),
    ] if t is not None]

    x_vals = [p[0] for p in pos.values()]
    y_vals = [p[1] for p in pos.values()]

    title_suffix = f" · {len(matched_nodes)} matched" if matched_nodes else ""
    fig = go.Figure(data=traces, layout=go.Layout(
        title=dict(
            text=f"CTE Dependency Graph · {len(G.nodes)} nodes, {len(G.edges)} edges{title_suffix}",
            font=dict(size=16), x=0.5,
        ),
        showlegend=True,
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        hovermode="closest",
        xaxis=dict(visible=False, range=[min(x_vals)-2, max(x_vals)+2]),
        yaxis=dict(visible=False, scaleanchor="x", scaleratio=1,
                   range=[min(y_vals)-2, max(y_vals)+2]),
        annotations=annotations,
        margin=dict(l=20, r=20, t=60, b=20),
        paper_bgcolor="white", plot_bgcolor="#F8FAFC",
        height=700, dragmode="pan",
        modebar_add=["pan2d", "zoomIn2d", "zoomOut2d", "resetScale2d"],
    ))
    return fig


# ═══════════════════════════════════════════════════════════════
# INTERACTIVE GRAPH — PYVIS
# ═══════════════════════════════════════════════════════════════

def interactive_graph(
    dependencies: Dict[str, List[str]],
    height: str = "720px",
    layout: str = "hierarchical",
    output_path: Optional[str] = None,
    highlight_nodes: Set[str] = None,
    matched_nodes: Set[str] = None,
    duplicate_nodes: Set[str] = None,
    cte_sql_map: Dict[str, str] = None,   # ✅ preferred
    ctes: Dict[str, any] = None,          # ✅ optional fallback
    search_column: str = None
) -> str:
    """
    Build a fully interactive pyvis dependency graph and save it as HTML.

    Highlight states (when a column search is active):
      🟡 matched_nodes   → yellow  (direct column match)
      🔵/🟢 highlight_nodes → normal colour, full opacity (related)
      🩶 everything else → grey, 30% opacity (unrelated)
    """
    highlight_nodes = highlight_nodes or set()
    matched_nodes   = matched_nodes   or set()
    duplicate_nodes = duplicate_nodes or set()
    searching       = bool(highlight_nodes or matched_nodes or duplicate_nodes)

    G = create_graph(dependencies)
    dependent_nodes = set(dependencies.keys())

    net = Network(
        height=height,
        width="100%",
        directed=True,
        bgcolor=COLORS["background"],
        font_color=COLORS["font"],
    )

    # ── Empty state ──────────────────────────────────────────
    if len(G.nodes) == 0:
        net.add_node("empty", label="No dependencies found", shape="ellipse",
                     color={"background": "#E2E8F0", "border": "#CBD5E1"},
                     font={"size": 16})
        return _save_and_return(net, output_path, cte_sql_map)

    # ── Nodes ────────────────────────────────────────────────
    for node in G.nodes():
        kind  = _classify_node(node, G, dependent_nodes)
        size  = _node_size(node, G)

        # Resolve colour based on highlight state
        if node in matched_nodes:
            bg, border, hl_bg = "#F59E0B", "#B45309", "#FCD34D"
            opacity = 1.0
        elif not searching or node in highlight_nodes:
            palette = COLORS[kind]
            bg, border, hl_bg = palette["bg"], palette["border"], palette["highlight"]
            opacity = 1.0
        else:
            bg, border, hl_bg = "#E2E8F0", "#CBD5E1", "#F1F5F9"
            opacity = 0.3

        net.add_node(
            node,
            label=node,
            title=build_cte_tooltip(
                    node,
                    G,
                    kind,
                    cte_sql_map=cte_sql_map,
                    search_column=search_column,
            ),
            shape="box" if kind in ("cte", "terminal") else "ellipse",
            size=size,
            color={
                "background": bg,
                "border":     border,
                "highlight":  {"background": hl_bg, "border": border},
                "hover":      {"background": hl_bg, "border": border},
            },
            font={
                "size":  max(11, min(14, 10 + size // 6)),
                "color": "#FFFFFF" if opacity == 1.0 else "#94A3B8",
                "bold":  True,
            },
            borderWidth=2,
            borderWidthSelected=3,
            shadow=True,
            opacity=opacity,
        )

    # ── Edges ────────────────────────────────────────────────
    for source, target in G.edges():
        in_sub = source in highlight_nodes and target in highlight_nodes
        is_hot = (
            source in matched_nodes or target in matched_nodes
            or source in duplicate_nodes or target in duplicate_nodes
        )

        if not searching:
            color, width = COLORS["edge"], 1.5
        elif in_sub and is_hot:
            color, width = COLORS["edge_hot"], 2.5
        elif in_sub:
            color, width = COLORS["edge_highlight"], 2.0
        else:
            color, width = "#E2E8F0", 0.6

        net.add_edge(
            source, target,
            color={"color": color, "highlight": COLORS["edge_hot"]},
            width=width,
            smooth={"type": "cubicBezier", "forceDirection": "horizontal", "roundness": 0.4},
            arrows={"to": {"enabled": True, "scaleFactor": 0.9}},
            title=f"{source}  →  {target}",
        )

    # ── Physics / layout ─────────────────────────────────────
    if layout == "hierarchical":
        net.set_options(json.dumps({
            "layout":    {"hierarchical": PHYSICS_PRESETS["hierarchical"]},
            "physics":   {"enabled": False},
            "interaction": _interaction_options(),
            "edges":     {"font": {"size": 0}},
        }))
    else:
        net.set_options(json.dumps({
            "physics":   {"barnesHut": PHYSICS_PRESETS["barnes_hut"], "solver": "barnesHut"},
            "interaction": _interaction_options(),
        }))

    # ── Legend + metrics panel ────────────────────────────────
    metrics = _graph_metrics(G)
    _inject_info_panel(net, metrics, matched_nodes=matched_nodes, searching=searching)

    return _save_and_return(net, output_path, cte_sql_map)


# ═══════════════════════════════════════════════════════════════
# PYVIS HELPERS
# ═══════════════════════════════════════════════════════════════

def _interaction_options():
    return {
        "hover": False,
        "tooltipDelay": 150,

        "navigationButtons": True,
        "keyboard": True,
        "multiselect": True,
        "zoomView": True,

        # 🔥 ADD THESE
        "dragNodes": True,
        "dragView": True,
        "selectable": True,
        "hoverConnectedEdges": True,
    }


def _inject_info_panel(
    net: Network,
    metrics: Dict,
    matched_nodes: Set[str] = None,
    searching: bool = False,
) -> None:
    matched_nodes = matched_nodes or set()
    cycle_warning = (
        '<span style="color:#EF4444;font-weight:600">⚠ Cycle detected</span>'
        if metrics["has_cycles"] else ""
    )
    search_row = (
        f"<tr><td style='padding:2px 8px 2px 0;color:#64748B'>Matched</td>"
        f"<td style='font-weight:600;color:#F59E0B'>{len(matched_nodes)}</td></tr>"
        if searching else ""
    )
    panel_html = f"""
    <div id="info-panel" style="
        position:absolute; top:12px; left:12px; z-index:999;
        background:rgba(255,255,255,0.93); border:1px solid #E2E8F0;
        border-radius:10px; padding:12px 16px; font-family:sans-serif;
        font-size:13px; color:#1E293B; box-shadow:0 2px 8px rgba(0,0,0,.12);
        min-width:210px;">
      <div style="font-weight:700;font-size:14px;margin-bottom:8px">
        📊 Graph Overview {cycle_warning}
      </div>
      <table style="border-collapse:collapse;width:100%">
        <tr><td style="padding:2px 8px 2px 0;color:#64748B">Nodes</td>
            <td style="font-weight:600">{metrics['nodes']}</td></tr>
        <tr><td style="padding:2px 8px 2px 0;color:#64748B">Edges</td>
            <td style="font-weight:600">{metrics['edges']}</td></tr>
        <tr><td style="padding:2px 8px 2px 0;color:#64748B">Max depth</td>
            <td style="font-weight:600">{metrics['depth'] if metrics['depth'] >= 0 else '—'}</td></tr>
        <tr><td style="padding:2px 8px 2px 0;color:#64748B">Subgraphs</td>
            <td style="font-weight:600">{metrics['components']}</td></tr>
        {search_row}
      </table>
      <div style="margin-top:10px;border-top:1px solid #E2E8F0;padding-top:8px">
        <div style="margin-bottom:4px">
          <span style="display:inline-block;width:12px;height:12px;border-radius:50%;
            background:#3B82F6;margin-right:6px;vertical-align:middle"></span>Base table
        </div>
        <div style="margin-bottom:4px">
          <span style="display:inline-block;width:12px;height:12px;border-radius:2px;
            background:#10B981;margin-right:6px;vertical-align:middle"></span>CTE
        </div>
        <div style="margin-bottom:4px">
          <span style="display:inline-block;width:12px;height:12px;border-radius:2px;
            background:#F59E0B;margin-right:6px;vertical-align:middle"></span>Terminal / Matched
        </div>
        <div>
          <span style="display:inline-block;width:12px;height:12px;border-radius:2px;
            background:#CBD5E1;margin-right:6px;vertical-align:middle"></span>Unrelated (dimmed)
        </div>
      </div>
      <div style="margin-top:8px;font-size:11px;color:#94A3B8">
        Scroll to zoom · Drag to pan · Click to select
      </div>
    </div>
    """
    net.html = net.html.replace("</body>", f"{panel_html}</body>")


def _save_and_return(net, output_path, cte_sql_map=None):
    if output_path is None:
        output_path = "graph.html"

    net.save_graph(output_path)

    # ✅ Inject custom JS + SQL viewer
    with open(output_path, "r", encoding="utf-8") as f:
        html = f.read()

    # ✅ Build node → SQL mapping
    node_sql_map = {}
    if cte_sql_map:
        for node in net.nodes:
            node_id = node["id"]
            cte = node_id.split(".")[0]
            node_sql_map[node_id] = cte_sql_map.get(cte, "No SQL available")

    injection = f"""
    <div style="
        position: fixed;
        bottom: 0;
        left: 0;
        width: 100%;
        height: 250px;
        background: #111;
        color: #0f0;
        border-top: 2px solid #333;
        overflow: auto;
        font-family: monospace;
        padding: 10px;
        white-space: pre;
        z-index: 9999;
    " id="sql-viewer">
        Click a node to view SQL here
    </div>

    <script>
        var node_sql_map = {json.dumps(node_sql_map)};

        network.on("click", function(params) {{
            if (params.nodes.length > 0) {{
                var node = params.nodes[0];
                var sql = node_sql_map[node] || "No SQL available";

                document.getElementById("sql-viewer").innerText = sql;
            }}
        }});
    </script>
    """

    # inject before closing body
    html = html.replace("</body>", injection + "\n</body>")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    return output_path


# ═══════════════════════════════════════════════════════════════
# EXPORT — JSON
# ═══════════════════════════════════════════════════════════════

def export_graph_json(
    dependencies: Dict[str, List[str]],
    include_metrics: bool = True,
) -> Dict:
    G = create_graph(dependencies)
    dependent_nodes = set(dependencies.keys())

    nodes = []
    for node in G.nodes():
        kind = _classify_node(node, G, dependent_nodes)
        nodes.append({
            "id":           node,
            "kind":         kind,
            "in_degree":    G.in_degree(node),
            "out_degree":   G.out_degree(node),
            "predecessors": list(G.predecessors(node)),
            "successors":   list(G.successors(node)),
        })

    edges = [{"index": i, "source": u, "target": v}
             for i, (u, v) in enumerate(G.edges())]

    adjacency = {node: list(G.successors(node)) for node in G.nodes()}

    payload: Dict = {"nodes": nodes, "edges": edges, "adjacency": adjacency}
    if include_metrics:
        payload["metadata"] = _graph_metrics(G)

    return payload