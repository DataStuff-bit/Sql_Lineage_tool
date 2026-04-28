import plotly.graph_objects as go
import math
import streamlit as st
import networkx as nx
import regex as re

# ── Must be FIRST Streamlit call ────────────────────────────
st.set_page_config(
    layout="wide",
    page_title="SQL Lineage Visualizer",
    page_icon="🔥",
)

import sqlglot
from analyzer.parser import parse_query
from analyzer.cte_extractor import extract_ctes
from analyzer.dependency import build_dependencies
from analyzer.lineage import build_lineage
from utils.graph import (
    draw_dependency_graph,
    interactive_graph,
    create_graph,
    highlight_column,
    detect_duplicate_risk,
    extract_joins,
)
from analyzer.column_graph import (
    build_column_graph,
    trace_column_paths,
    build_reverse_graph,
    get_column_dependencies,
)
from collections import defaultdict

# ═══════════════════════════════════════════════════════════════
# STYLING
# ═══════════════════════════════════════════════════════════════
st.markdown("""
<style>
    .block-container { padding-top: 1.2rem; }
    div[data-testid="metric-container"] {
        background: #F8FAFC; border: 1px solid #E2E8F0;
        border-radius: 8px; padding: 10px 16px;
    }
    .stTabs [data-baseweb="tab"] { font-size: 13px; padding: 6px 14px; }
    .pill {
        display: inline-block; padding: 2px 10px; border-radius: 20px;
        font-size: 12px; font-weight: 600; margin: 2px;
    }
    .pill-blue  { background:#EEF2FF; color:#4F46E5; }
    .pill-green { background:#ECFDF5; color:#047857; }
    .pill-amber { background:#FFFBEB; color:#B45309; }
    .pill-red   { background:#FEF2F2; color:#DC2626; }
</style>
""", unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════
# MODULE-LEVEL HELPERS  (not nested inside tabs)
# ═══════════════════════════════════════════════════════════════

def strip_comments(sql: str) -> str:
    """Remove -- and /* */ comments, respecting string literals."""
    result = []; i = 0; in_single = in_double = False
    while i < len(sql):
        c = sql[i]
        if c == "'" and not in_double: in_single = not in_single; result.append(c); i += 1; continue
        if c == '"' and not in_single: in_double = not in_double; result.append(c); i += 1; continue
        if in_single or in_double: result.append(c); i += 1; continue
        if sql[i:i+2] == '--':
            while i < len(sql) and sql[i] != '\n': i += 1
            result.append('\n'); continue
        if sql[i:i+2] == '/*':
            i += 2
            while i < len(sql) - 1 and sql[i:i+2] != '*/': i += 1
            i += 2; result.append(' '); continue
        result.append(c); i += 1
    return ''.join(result)


def find_matching_paren(sql: str, start: int) -> int:
    depth = 0; i = start; in_single = in_double = False
    while i < len(sql):
        c = sql[i]
        if c == "'" and not in_double: in_single = not in_single
        elif c == '"' and not in_single: in_double = not in_double
        elif not in_single and not in_double:
            if c == '(': depth += 1
            elif c == ')':
                depth -= 1
                if depth == 0: return i
        i += 1
    return -1


def extract_ctes_for_count(sql: str) -> dict:
    """
    Robust CTE extractor for the Row Counter tab.
    Handles: "quoted", [bracketed], `backtick`, plain names,
             nested parens, WITH RECURSIVE, inline + block comments.
    """
    sql = strip_comments(sql)
    with_match = re.compile(r'\bWITH\b\s*(?:RECURSIVE\s+)?', re.IGNORECASE).search(sql)
    if not with_match:
        return {}
    pos = with_match.end(); ctes = {}
    name_pat = re.compile(
        r'\s*(?:"([^"]+)"|`([^`]+)`|\[([^\]]+)\]|(\w+))\s*(?:\([^)]*\))?\s+AS\s*\(',
        re.IGNORECASE,
    )
    while pos < len(sql):
        while pos < len(sql) and sql[pos] in (' ', '\t', '\n', '\r', ','): pos += 1
        m = name_pat.match(sql, pos)
        if not m: break
        cte_name = m.group(1) or m.group(2) or m.group(3) or m.group(4)
        open_paren = m.end() - 1
        close_paren = find_matching_paren(sql, open_paren)
        if close_paren == -1: break
        ctes[cte_name] = sql[open_paren + 1:close_paren].strip()
        pos = close_paren + 1
        peek = sql[pos:].lstrip().upper()
        if not peek or any(peek.startswith(k) for k in ('SELECT','INSERT','UPDATE','DELETE','MERGE')):
            break
    return ctes


def build_count_query(ctes: dict) -> str:
    """Single UNION ALL query returning (cte_name, row_count) for every CTE."""
    cte_blocks = [f"  {name} AS (\n    {body}\n  )" for name, body in ctes.items()]
    union_blocks = [
        f"  SELECT '{name}' AS cte_name, COUNT(*) AS row_count FROM {name}"
        for name in ctes
    ]
    return (
        "WITH\n"
        + ",\n\n".join(cte_blocks)
        + "\n\n"
        + "\nUNION ALL\n".join(union_blocks)
        + "\nORDER BY cte_name;"
    )


def get_ctes_with_column(lineage: dict, column: str) -> set[str]:
    column = column.strip().lower()
    return {
        cte
        for cte, cols in lineage.items()
        for col in cols
        if column in col.get("output", "").lower()
        or any(column in str(s).lower() for s in col.get("sources", []))
    }


def get_dependency_subgraph(G: nx.DiGraph, highlight_ctes: set[str]) -> set[str]:
    related = set(highlight_ctes)
    for node in highlight_ctes:
        if node in G:
            related |= nx.ancestors(G, node)
            related |= nx.descendants(G, node)
    return related


def find_duplicate_ctes(
    lineage: dict, cte_sql_map: dict[str, str]
) -> tuple[set[str], dict[str, list[str]]]:
    duplicate_ctes: set[str] = set()
    duplicate_notes: dict[str, list[str]] = {}

    for cte, cols in lineage.items():
        alias_counts: dict[str, int] = {}
        for col in cols:
            output = str(col.get("output", "")).strip().lower()
            if not output: continue
            alias_counts[output] = alias_counts.get(output, 0) + 1
        for alias, count in alias_counts.items():
            if count > 1:
                duplicate_ctes.add(cte)
                duplicate_notes.setdefault(cte, []).append(
                    f"Column alias `{alias}` appears {count}× in `{cte}`."
                )

    output_map: dict[str, set[str]] = {}
    for cte, cols in lineage.items():
        for col in cols:
            output = str(col.get("output", "")).strip().lower()
            if not output: continue
            output_map.setdefault(output, set()).add(cte)
    for output, ctes_with_output in output_map.items():
        if len(ctes_with_output) > 1:
            note = (
                f"Output `{output}` produced by multiple CTEs: "
                + ", ".join(sorted(ctes_with_output))
            )
            for cte in ctes_with_output:
                duplicate_ctes.add(cte)
                duplicate_notes.setdefault(cte, []).append(note)

    for cte, sql in cte_sql_map.items():
        risk = detect_duplicate_risk(sql)
        if risk:
            duplicate_ctes.add(cte)
            duplicate_notes.setdefault(cte, []).append(risk)

    return duplicate_ctes, duplicate_notes


def cte_complexity_score(sql: str) -> int:
    """Rough complexity score: 1 pt each for JOIN, subquery, CASE, window fn, GROUP BY."""
    sql_up = sql.upper()
    score = 0
    score += sql_up.count(" JOIN ")
    score += sql_up.count("SELECT", 1)      # nested SELECTs (skip the first)
    score += sql_up.count("CASE ")
    score += sql_up.count("OVER (") + sql_up.count("OVER(")
    score += sql_up.count("GROUP BY")
    return score


def draw_highlighted_graph(
    deps: dict,
    highlight_nodes: set[str],
    matched_nodes: set[str],
    duplicate_nodes: set[str] = None,
):
    G = create_graph(deps)
    if len(G.nodes) == 0:
        return go.Figure()

    dependent_nodes = set(deps.keys())
    all_nodes = set(G.nodes())
    source_nodes = all_nodes - dependent_nodes
    duplicate_nodes = duplicate_nodes or set()

    try:
        layers: dict = {}
        for node in nx.topological_sort(G):
            preds = list(G.predecessors(node))
            layers[node] = max((layers[p] for p in preds), default=-1) + 1
        layer_groups: dict = defaultdict(list)
        for node, layer in layers.items():
            layer_groups[layer].append(node)
        pos = {}
        for layer, nodes in layer_groups.items():
            for i, node in enumerate(sorted(nodes)):
                y = (i - (len(nodes) - 1) / 2.0) * 2.0
                pos[node] = (layer * 3.0, y)
    except nx.NetworkXUnfeasible:
        pos = nx.spring_layout(G, k=2.5, seed=42)

    in_deg = dict(G.in_degree())
    out_deg = dict(G.out_degree())
    searching = bool(highlight_nodes or matched_nodes)

    def node_color(n):
        if n in duplicate_nodes and n in matched_nodes: return "#EF4444"  # red — both
        if n in duplicate_nodes:  return "#F97316"  # orange — dup risk
        if n in matched_nodes:    return "#F59E0B"  # yellow — column match
        if not searching or n in highlight_nodes:
            return "#3B82F6" if n in source_nodes else "#10B981"
        return "#CBD5E1"

    def node_opacity(n):
        return 1.0 if (not searching or n in highlight_nodes or n in matched_nodes or n in duplicate_nodes) else 0.2

    def edge_style(u, v):
        in_sub = u in highlight_nodes and v in highlight_nodes
        is_hot = u in matched_nodes or v in matched_nodes
        if not searching:        return "#94A3B8", 1.2
        if in_sub and is_hot:    return "#F59E0B", 2.5
        if in_sub:               return "#64748B", 2.0
        return "#E2E8F0", 0.5

    edge_traces, annotations = [], []
    for u, v in G.edges():
        x0, y0 = pos[u]; x1, y1 = pos[v]
        color, width = edge_style(u, v)
        edge_traces.append(go.Scatter(
            x=[x0, x1, None], y=[y0, y1, None], mode="lines",
            line=dict(width=width, color=color),
            hoverinfo="none", showlegend=False,
        ))
        dx, dy = x1 - x0, y1 - y0
        shrink = 0.18
        annotations.append(dict(
            x=x1 - dx * shrink, y=y1 - dy * shrink, ax=x0, ay=y0,
            xref="x", yref="y", axref="x", ayref="y",
            showarrow=True, arrowhead=2, arrowsize=1.2,
            arrowwidth=1.5, arrowcolor=color,
        ))

    def make_node_trace(node_list, name, symbol):
        if not node_list: return None
        sizes   = [max(20, min(50, 20 + (in_deg[n] + out_deg[n]) * 3)) for n in node_list]
        colors  = [node_color(n) for n in node_list]
        opacities = [node_opacity(n) for n in node_list]
        return go.Scatter(
            x=[pos[n][0] for n in node_list],
            y=[pos[n][1] for n in node_list],
            mode="markers+text",
            marker=dict(symbol=symbol, size=sizes, color=colors,
                        opacity=opacities, line=dict(width=2, color="#475569")),
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
        make_node_trace(list(source_nodes),    "Base tables",   "circle"),
        make_node_trace(list(dependent_nodes), "CTEs / Derived","square"),
    ] if t is not None]

    x_vals = [p[0] for p in pos.values()]
    y_vals = [p[1] for p in pos.values()]
    n_matched = len(matched_nodes)
    n_dup = len(duplicate_nodes)
    title_parts = [f"{len(G.nodes)} nodes"]
    if n_matched: title_parts.append(f"{n_matched} matched")
    if n_dup:     title_parts.append(f"{n_dup} dup-risk")

    return go.Figure(data=traces, layout=go.Layout(
        title=dict(text="Dependency Graph · " + " · ".join(title_parts), font=dict(size=15), x=0.5),
        showlegend=True,
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        hovermode="closest",
        xaxis=dict(visible=False, range=[min(x_vals)-2, max(x_vals)+2]),
        yaxis=dict(visible=False, scaleanchor="x", scaleratio=1, range=[min(y_vals)-2, max(y_vals)+2]),
        annotations=annotations,
        margin=dict(l=20, r=20, t=60, b=20),
        paper_bgcolor="white", plot_bgcolor="#F8FAFC",
        height=700, dragmode="pan",
        modebar_add=["pan2d", "zoomIn2d", "zoomOut2d", "resetScale2d"],
    ))


# ═══════════════════════════════════════════════════════════════
# SIDEBAR
# ═══════════════════════════════════════════════════════════════

with st.sidebar:
    st.header("⚙️ Settings")

    st.subheader("🎨 Graph")
    graph_layout = st.radio("Default layout", ["Hierarchical", "Force-directed"], horizontal=True)
    show_edge_labels = st.toggle("Show edge labels", value=False)

    st.divider()

    st.subheader("🔍 Search")
    search_mode = st.radio("Search mode", ["Contains", "Exact", "Regex"], horizontal=True)
    search_sources = st.toggle("Search in source columns too", value=True)

    st.divider()

    st.subheader("📋 History")
    if "query_history" not in st.session_state:
        st.session_state.query_history = []
    if st.session_state.query_history:
        selected_hist = st.selectbox(
            "Recent queries",
            options=[""] + [f"Query {i+1} ({len(q)} chars)" for i, q in enumerate(st.session_state.query_history)],
        )
        if selected_hist:
            idx = int(selected_hist.split()[1]) - 1
            st.session_state["restore_query"] = st.session_state.query_history[idx]
    if st.button("🗑 Clear history"):
        st.session_state.query_history = []
        st.rerun()


# ═══════════════════════════════════════════════════════════════
# TITLE + QUERY INPUT
# ═══════════════════════════════════════════════════════════════

st.title("🔥 SQL Lineage & CTE Visualizer")

default_query = st.session_state.pop("restore_query", "")
query = st.text_area(
    "Paste your SQL query here",
    height=220,
    value=default_query,
    placeholder="WITH cte1 AS (...), cte2 AS (...)\nSELECT * FROM cte2;",
)

col_run, col_fmt, col_clear = st.columns([1, 1, 4])
run_clicked = col_run.button("▶ Analyse", type="primary", use_container_width=True)
fmt_clicked = col_fmt.button("✨ Format SQL", use_container_width=True)

if fmt_clicked and query:
    try:
        formatted = sqlglot.transpile(query, pretty=True)[0]
        st.code(formatted, language="sql")
    except Exception:
        st.warning("Could not format SQL.")

if not query:
    st.info("Paste a SQL query above to begin.")
    st.stop()

# Save to history (deduplicated, max 10)
if query not in st.session_state.query_history:
    st.session_state.query_history = ([query] + st.session_state.query_history)[:10]


# ═══════════════════════════════════════════════════════════════
# PARSE  (cached by query hash)
# ═══════════════════════════════════════════════════════════════

@st.cache_data(show_spinner="Parsing query…")
def run_analysis(query: str):
    parsed = parse_query(query)
    ctes = extract_ctes(parsed)
    deps = build_dependencies(ctes)
    cte_sql_map = {name: expr.sql(pretty=True) for name, expr in ctes.items()}
    lineage, final_lineage = build_lineage(ctes, parsed)
    return parsed, ctes, deps, cte_sql_map, lineage, final_lineage


try:
    parsed, ctes, deps, cte_sql_map, lineage, final_lineage = run_analysis(query)
    duplicate_ctes, duplicate_notes = find_duplicate_ctes(lineage, cte_sql_map)
except Exception as e:
    st.error("❌ Error parsing SQL query")
    with st.expander("Details"):
        st.exception(e)
    st.stop()

G = create_graph(deps)

# ── All columns for autocomplete ─────────────────────────────
all_columns: list[str] = sorted({
    col.get("output", "")
    for cols in lineage.values()
    for col in cols
    if col.get("output")
})


# ═══════════════════════════════════════════════════════════════
# COLUMN SEARCH BAR
# ═══════════════════════════════════════════════════════════════

st.markdown("---")
st.markdown("### 🔍 Column Search")
s_col, c_col = st.columns([5, 1])

with s_col:
    column_search = st.selectbox(
        "Search",
        options=[""] + all_columns,
        format_func=lambda x: "— show all —" if x == "" else x,
        index=0,
        label_visibility="collapsed",
    )
with c_col:
    if st.button("✕ Clear", use_container_width=True):
        column_search = ""

matched_ctes: set[str] = set()
subgraph_nodes: set[str] = set()

if column_search:
    matched_ctes = get_ctes_with_column(lineage, column_search)
    subgraph_nodes = get_dependency_subgraph(G, matched_ctes)
    if matched_ctes:
        st.success(
            f"**'{column_search}'** found in {len(matched_ctes)} CTE(s): "
            + ", ".join(f"`{c}`" for c in sorted(matched_ctes))
        )
    else:
        st.warning(f"No CTEs contain a column matching **'{column_search}'**.")


# ═══════════════════════════════════════════════════════════════
# SUMMARY METRICS
# ═══════════════════════════════════════════════════════════════

st.markdown("---")
st.markdown("### 📊 Query Summary")

c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("CTEs",           len(ctes))
c2.metric("Dependencies",   sum(len(v) for v in deps.values()))
c3.metric("Final Columns",  len(final_lineage))
c4.metric("Matched CTEs",   len(matched_ctes) if column_search else "—")
c5.metric("Duplicate Risks",len(duplicate_ctes) if duplicate_ctes else "✅ 0")

# Complexity bar
if cte_sql_map:
    st.markdown("**CTE Complexity Scores**")
    scores = {name: cte_complexity_score(sql) for name, sql in cte_sql_map.items()}
    max_score = max(scores.values()) or 1
    cols_complexity = st.columns(min(len(scores), 6))
    for i, (name, score) in enumerate(sorted(scores.items(), key=lambda x: -x[1])):
        badge = "🔴" if score >= 5 else "🟡" if score >= 2 else "🟢"
        cols_complexity[i % 6].metric(f"{badge} {name}", f"score {score}")

# Execution flow
try:
    execution_order = list(nx.topological_sort(G))
    st.markdown("**Execution Flow:**")
    flow_parts = []
    for node in execution_order:
        if node in matched_ctes or node in duplicate_ctes:
            flow_parts.append(f"**:orange[{node}]**")
        elif node in subgraph_nodes:
            flow_parts.append(f"**{node}**")
        else:
            flow_parts.append(f":gray[{node}]" if column_search else node)
    st.markdown(" → ".join(flow_parts))
except Exception:
    st.warning("⚠️ Cycle detected — could not determine execution order.")

st.markdown("---")


# ═══════════════════════════════════════════════════════════════
# TABS
# ═══════════════════════════════════════════════════════════════

tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
    "📌 CTE Breakdown",
    "🔗 Dependency Graph",
    "🧬 Column Lineage",
    "🔗 Column Paths",
    "🧭 Column Dependency",
    "📊 Row Counter",
    "🛠 Debugger",
])


# ── TAB 1: CTE Breakdown ─────────────────────────────────────
with tab1:
    st.subheader("CTE Step-by-Step View")

    if not ctes:
        st.info("No CTEs found in the query.")
    else:
        t1_left, t1_right = st.columns([3, 1])
        with t1_left:
            show_all = st.toggle(
                "Show all CTEs",
                value=not bool(column_search),
                help="When a column is searched, toggle off to see only matched CTEs.",
            )
        with t1_right:
            sort_by = st.selectbox("Sort by", ["Definition order", "Complexity", "Name"], label_visibility="collapsed")

        cte_items = list(ctes.items())
        if sort_by == "Complexity":
            cte_items = sorted(cte_items, key=lambda x: -cte_complexity_score(cte_sql_map.get(x[0], "")))
        elif sort_by == "Name":
            cte_items = sorted(cte_items, key=lambda x: x[0])

        for i, (name, expr) in enumerate(cte_items, start=1):
            is_matched  = name in matched_ctes
            is_dup      = name in duplicate_ctes
            in_subgraph = name in subgraph_nodes

            if column_search and not show_all and not in_subgraph:
                continue

            badges = []
            if is_matched:  badges.append("🟡 Column match")
            if is_dup:      badges.append("🟠 Dup risk")
            if in_subgraph and not is_matched: badges.append("🔵 Related")
            score = cte_complexity_score(cte_sql_map.get(name, ""))
            complexity_badge = "🔴" if score >= 5 else "🟡" if score >= 2 else "🟢"
            badges.append(f"{complexity_badge} complexity {score}")

            label = f"Step {i}: `{name}`  {'  '.join(badges)}"
            with st.expander(label, expanded=is_matched):
                st.code(expr.sql(), language="sql")

                # Matched columns inline
                if is_matched and column_search:
                    matching_cols = [
                        col for col in lineage.get(name, [])
                        if column_search.lower() in col.get("output", "").lower()
                        or any(column_search.lower() in str(s).lower() for s in col.get("sources", []))
                    ]
                    if matching_cols:
                        st.markdown("**Matched columns:**")
                        for col in matching_cols:
                            st.markdown(f"- `{col['output']}` ← `{col['sources']}`")

                # Duplicate notes inline
                if is_dup and name in duplicate_notes:
                    st.warning("Duplicate risk: " + "; ".join(duplicate_notes[name]))


# ── TAB 2: Dependency Graph ───────────────────────────────────
with tab2:
    st.subheader("Dependency Visualization")

    if not deps:
        st.info("No dependencies found.")
    else:
        g_left, g_right = st.columns([3, 1])
        with g_left:
            graph_mode = st.radio("Graph type", ["Static (Plotly)", "Interactive (pyvis)"], horizontal=True)
        with g_right:
            if st.button("📥 Export PNG", help="Use the camera icon in the Plotly toolbar"):
                st.info("Use the 📷 icon in the graph toolbar to download as PNG.")

        # Legend pills
        legend_cols = st.columns(4)
        legend_cols[0].markdown('<span class="pill pill-blue">🔵 Base table</span>', unsafe_allow_html=True)
        legend_cols[1].markdown('<span class="pill pill-green">🟢 CTE</span>', unsafe_allow_html=True)
        legend_cols[2].markdown('<span class="pill pill-amber">🟡 Column match</span>', unsafe_allow_html=True)
        legend_cols[3].markdown('<span class="pill pill-red">🟠 Dup risk</span>', unsafe_allow_html=True)

        if graph_mode == "Static (Plotly)":
            fig = draw_highlighted_graph(deps, subgraph_nodes, matched_ctes, duplicate_ctes)
            st.plotly_chart(fig, use_container_width=True)
        else:
            html_path = interactive_graph(
                deps,
                ctes=ctes,
                cte_sql_map=cte_sql_map,
                search_column=column_search,
                highlight_nodes=subgraph_nodes,
                matched_nodes=matched_ctes,
                duplicate_nodes=duplicate_ctes,
            )
            with open(html_path, "r", encoding="utf-8") as f:
                st.components.v1.html(f.read(), height=680, scrolling=False)


# ── TAB 3: Column Lineage ─────────────────────────────────────
with tab3:
    st.subheader("Column-Level Lineage")

    if not lineage:
        st.info("No lineage information available.")
    else:
        display_lineage = (
            {k: v for k, v in lineage.items() if k in subgraph_nodes}
            if column_search and subgraph_nodes else lineage
        )

        # Export lineage as CSV
        lineage_rows = []
        for cte, cols in lineage.items():
            for col in cols:
                lineage_rows.append({
                    "cte": cte,
                    "output_column": col.get("output", ""),
                    "sources": str(col.get("sources", "")),
                })
        import pandas as pd
        import io
        lineage_df = pd.DataFrame(lineage_rows)
        csv_buf = io.StringIO()
        lineage_df.to_csv(csv_buf, index=False)
        st.download_button(
            "⬇ Export lineage as CSV",
            data=csv_buf.getvalue().encode(),
            file_name="column_lineage.csv",
            mime="text/csv",
        )

        for cte, cols in display_lineage.items():
            is_matched = cte in matched_ctes
            prefix = "🟡" if is_matched else "🔹"
            st.markdown(f"### {prefix} {cte}")

            if not cols:
                st.write("No columns detected")
            else:
                for col in cols:
                    output  = col["output"]
                    sources = col["sources"]
                    if column_search and column_search.lower() in output.lower():
                        st.markdown(f"> 🟡 **`{output}`** ← `{sources}`")
                    else:
                        st.write(f"**{output}** ← {sources}")

        st.markdown("---")
        st.markdown("### 🎯 Final Output")
        for col in final_lineage:
            output = col["output"]
            if column_search and column_search.lower() in output.lower():
                st.markdown(f"> 🟡 **`{output}`** ← `{col['sources']}`")
            else:
                st.write(f"**{output}** ← {col['sources']}")


# ── TAB 4: Column Path Tracing ────────────────────────────────
with tab4:
    st.subheader("🔗 Column Path Tracing")

    if not column_search:
        st.info("Select a column in the search bar above to trace its path through CTEs.")
    else:
        col_graph = build_column_graph(lineage)
        final_cte = list(lineage.keys())[-1]
        final_outputs = {
            f"{final_cte}.{col['output']}".lower()
            for col in final_lineage
        }
        paths = trace_column_paths(col_graph, column_search, final_outputs)

        if not paths:
            st.warning(f"No propagation paths found for `{column_search}`.")
        else:
            st.success(f"Found **{len(paths)} path(s)** for `{column_search}`")
            for i, path in enumerate(paths, 1):
                st.markdown(f"### 🛣️ Path {i}")
                formatted = []
                seen_ctes = set()

                for node in path:
                    col  = node.split(".")[-1]
                    cte  = node.split(".")[0]
                    formatted.append(f"🟡 **`{node}`**" if col.lower() == column_search.lower() else f"`{node}`")

                    if cte not in seen_ctes:
                        seen_ctes.add(cte)
                        if cte in cte_sql_map:
                            with st.expander(f"📄 SQL for `{cte}`"):
                                st.code(highlight_column(cte_sql_map[cte], column_search), language="sql")
                                risk = detect_duplicate_risk(cte_sql_map[cte])
                                if risk: st.warning(risk)
                                joins = extract_joins(cte_sql_map[cte])
                                if joins:
                                    st.markdown("**Joins:**")
                                    for j in joins: st.code(j, language="sql")

                st.markdown(" → ".join(formatted))

                # Transformation detection
                transformations = [
                    (path[j].split(".")[-1], path[j+1].split(".")[-1])
                    for j in range(len(path) - 1)
                    if path[j].split(".")[-1] != path[j+1].split(".")[-1]
                ]
                if transformations:
                    st.markdown("**🔄 Transformations (column renamed):**")
                    for src, tgt in transformations:
                        st.markdown(f"- `{src}` → `{tgt}`")
                else:
                    st.success("✅ Column name unchanged throughout path.")
                st.markdown("---")


# ── TAB 5: Column Dependency Explorer ────────────────────────
with tab5:
    st.subheader("🧭 Column Dependency Explorer")

    if not column_search:
        st.info("Select a column in the search bar above to explore dependencies.")
    else:
        col_graph = build_column_graph(lineage)
        rev_graph = build_reverse_graph(col_graph)
        upstream, current, downstream = get_column_dependencies(col_graph, rev_graph, column_search)

        u_col, c_col_disp, d_col = st.columns(3)

        with u_col:
            st.markdown(f"### 🔙 Upstream  `({len(upstream)})`")
            if not upstream:
                st.write("No upstream")
            for u in sorted(upstream):
                st.markdown(f"- `{u}`")
                cte = u.split(".")[0]
                if cte in cte_sql_map:
                    with st.expander(f"SQL: `{cte}`"):
                        st.code(highlight_column(cte_sql_map[cte], column_search), language="sql")
                        risk = detect_duplicate_risk(cte_sql_map[cte])
                        if risk: st.warning(risk)

        with c_col_disp:
            st.markdown(f"### ➡️ Current  `({len(current)})`")
            for c in current:
                st.markdown(f"- 🟡 `{c}`")
                cte = c.split(".")[0]
                if cte in cte_sql_map:
                    with st.expander(f"SQL: `{cte}`"):
                        st.code(highlight_column(cte_sql_map[cte], column_search), language="sql")

        with d_col:
            st.markdown(f"### 🔜 Downstream  `({len(downstream)})`")
            if not downstream:
                st.write("No downstream")
            for d in sorted(downstream):
                st.markdown(f"- `{d}`")
                cte = d.split(".")[0]
                if cte in cte_sql_map:
                    with st.expander(f"SQL: `{cte}`"):
                        st.code(highlight_column(cte_sql_map[cte], column_search), language="sql")
                        risk = detect_duplicate_risk(cte_sql_map[cte])
                        if risk: st.warning(risk)


# ── TAB 6: Row Counter ────────────────────────────────────────
with tab6:
    st.subheader("📊 CTE Row Counter")
    st.caption("Paste your SQL below → get a ready-to-run COUNT(*) query for every CTE.")

    rc_sql = st.text_area(
        "SQL for row counting",
        height=220,
        value=query,   # pre-fill with the query already entered above
        placeholder="WITH cte1 AS (...), cte2 AS (...)\nSELECT * FROM cte2;",
        key="row_counter_sql",
    )

    if rc_sql.strip():
        rc_ctes = extract_ctes_for_count(rc_sql)

        if not rc_ctes:
            st.error("❌ No CTEs found. Check `WITH cte AS (...)` syntax.")
            with st.expander("🔍 Debug — stripped SQL"):
                st.code(strip_comments(rc_sql)[:3000], language="sql")
        else:
            names = list(rc_ctes.keys())
            st.success(f"✅ Found **{len(names)} CTE(s):** {', '.join(f'`{n}`' for n in names)}")

            count_query = build_count_query(rc_ctes)

            st.markdown("### ▶ Run this query to get row counts")
            st.caption("Works on Snowflake, BigQuery, Postgres, Redshift, DuckDB, etc.")
            st.code(count_query, language="sql")

            st.download_button(
                "⬇ Download as .sql",
                data=count_query.encode(),
                file_name="cte_row_counts.sql",
                mime="text/plain",
            )


# ── TAB 7: Debugger ───────────────────────────────────────────
with tab7:
    st.subheader("🛠 Debugger — Column & Duplicate Inspector")

    if not column_search:
        st.info("Search a column above to inspect where it appears and any duplicate risks.")
    else:
        if matched_ctes:
            st.markdown(
                f"**Tracked column:** `{column_search}` appears in {len(matched_ctes)} CTE(s): "
                + ", ".join(f"`{cte}`" for cte in sorted(matched_ctes))
            )
        else:
            st.warning(f"No CTEs contain `{column_search}`.")

        if duplicate_ctes:
            st.markdown("### 🟠 Duplicate risk candidates")
            for cte in sorted(duplicate_ctes):
                notes = duplicate_notes.get(cte, [])
                st.markdown(f"- `{cte}`")
                for note in notes:
                    st.markdown(f"  - {note}")
        else:
            st.success("✅ No duplicate-risk CTEs or repeated output columns detected.")

        st.markdown("---")
        st.markdown("### 🧠 Column Debugger")

        for cte, cols in lineage.items():
            matches = [
                col for col in cols
                if column_search.lower() in col.get("output", "").lower()
                or any(column_search.lower() in str(s).lower() for s in col.get("sources", []))
            ]
            if not matches:
                continue
            st.markdown(f"#### `{cte}`")
            for col in matches:
                st.markdown(f"- `{col['output']}` ← {col['sources']}")
            if cte in cte_sql_map:
                with st.expander(f"📄 Full SQL for `{cte}`"):
                    st.code(highlight_column(cte_sql_map[cte], column_search), language="sql")
                    risk = detect_duplicate_risk(cte_sql_map[cte])
                    if risk: st.warning(risk)
                    joins = extract_joins(cte_sql_map[cte])
                    if joins:
                        st.markdown("**Joins detected:**")
                        for j in joins: st.code(j, language="sql")

        if duplicate_ctes:
            st.markdown("---")
            st.markdown("### 🔶 Duplicate-risk nodes in dependency graph")
            html_path = interactive_graph(
                deps,
                ctes=ctes,
                cte_sql_map=cte_sql_map,
                search_column=column_search,
                highlight_nodes=subgraph_nodes,
                matched_nodes=matched_ctes,
                duplicate_nodes=duplicate_ctes,
            )
            with open(html_path, "r", encoding="utf-8") as f:
                st.components.v1.html(f.read(), height=680, scrolling=False)