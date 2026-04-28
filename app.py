import plotly.graph_objects as go
import math
import streamlit as st
import networkx as nx
import regex as re
import sqlglot
from analyzer.parser import parse_query
from analyzer.cte_extractor import extract_ctes
from analyzer.dependency import build_dependencies
from analyzer.lineage import build_lineage
from utils.graph import draw_dependency_graph, interactive_graph, create_graph
from analyzer.column_graph import (
    build_column_graph,
    trace_column_paths,
    build_reverse_graph,
    get_column_dependencies
)
from analyzer.column_graph import (
    build_column_graph,
    build_reverse_graph,
    trace_column_paths,
    get_column_dependencies
)

from utils.graph import (
    highlight_column,
    detect_duplicate_risk,
    extract_joins
)
st.set_page_config(layout="wide", page_title="SQL Lineage Visualizer")
st.title("🔥 SQL Lineage & CTE Visualizer")

# ═══════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════

def get_ctes_with_column(lineage: dict, column: str) -> set[str]:
    """Return CTE names whose output columns contain the search term."""
    column = column.strip().lower()
    return {
        cte
        for cte, cols in lineage.items()
        for col in cols
        if column in col.get("output", "").lower()
        or any(column in str(s).lower() for s in col.get("sources", []))
    }


def get_dependency_subgraph(G: nx.DiGraph, highlight_ctes: set[str]) -> set[str]:
    """
    For every matched CTE, walk ALL ancestors (what it depends on)
    and ALL descendants (what depends on it) so the full relevant
    slice of the graph is visible.
    """
    related = set(highlight_ctes)
    for node in highlight_ctes:
        if node in G:
            related |= nx.ancestors(G, node)
            related |= nx.descendants(G, node)
    return related


def find_duplicate_ctes(lineage: dict, cte_sql_map: dict[str, str]) -> tuple[set[str], dict[str, list[str]]]:
    duplicate_ctes: set[str] = set()
    duplicate_notes: dict[str, list[str]] = {}

    # Same output alias repeated in one CTE
    for cte, cols in lineage.items():
        alias_counts: dict[str, int] = {}
        for col in cols:
            output = str(col.get("output", "")).strip().lower()
            if not output:
                continue
            alias_counts[output] = alias_counts.get(output, 0) + 1
        for alias, count in alias_counts.items():
            if count > 1:
                duplicate_ctes.add(cte)
                duplicate_notes.setdefault(cte, []).append(
                    f"Column alias `{alias}` appears {count} times in `{cte}`."
                )

    # Same output alias across multiple CTEs
    output_map: dict[str, set[str]] = {}
    for cte, cols in lineage.items():
        for col in cols:
            output = str(col.get("output", "")).strip().lower()
            if not output:
                continue
            output_map.setdefault(output, set()).add(cte)

    for output, ctes_with_output in output_map.items():
        if len(ctes_with_output) > 1:
            note = (
                f"Output column `{output}` is produced by multiple CTEs: "
                + ", ".join(sorted(ctes_with_output))
            )
            for cte in ctes_with_output:
                duplicate_ctes.add(cte)
                duplicate_notes.setdefault(cte, []).append(note)

    # SQL-level duplicate/excessive join risk
    for cte, sql in cte_sql_map.items():
        risk = detect_duplicate_risk(sql)
        if risk:
            duplicate_ctes.add(cte)
            duplicate_notes.setdefault(cte, []).append(risk)

    return duplicate_ctes, duplicate_notes


def draw_highlighted_graph(deps: dict, highlight_nodes: set[str], matched_nodes: set[str], duplicate_nodes: set[str] = None):
    """
    Wrapper around draw_dependency_graph that injects highlight colours.
    highlight_nodes = ancestors + descendants (dimmed-but-visible)
    matched_nodes   = direct column matches (bright)
    """

    G = create_graph(deps)
    if len(G.nodes) == 0:
        return go.Figure()

    dependent_nodes = set(deps.keys())
    all_nodes = set(G.nodes())
    source_nodes = all_nodes - dependent_nodes

    # Topological hierarchical layout (reuse from graph utils)
    try:
        from collections import defaultdict
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

    duplicate_nodes = duplicate_nodes or set()

    def node_color(n):
        if n in matched_nodes or n in duplicate_nodes:
            return "#F59E0B"          # 🟡 direct column match / duplicate risk
        if n in highlight_nodes:
            return "#3B82F6" if n in source_nodes else "#10B981"  # normal colours
        return "#CBD5E1"              # 🩶 dimmed — not in subgraph

    def node_opacity(n):
        return 1.0 if (n in matched_nodes or n in duplicate_nodes or n in highlight_nodes or not highlight_nodes) else 0.25

    def edge_color(u, v):
        if u in highlight_nodes and v in highlight_nodes:
            return "#F59E0B" if (
                u in matched_nodes or v in matched_nodes or u in duplicate_nodes or v in duplicate_nodes
            ) else "#64748B"
        return "#E2E8F0"

    def edge_width(u, v):
        return 2.5 if (u in highlight_nodes and v in highlight_nodes) else 0.8

    # Edge traces
    edge_traces = []
    annotations = []
    for u, v in G.edges():
        x0, y0 = pos[u]
        x1, y1 = pos[v]
        ec = edge_color(u, v)
        ew = edge_width(u, v)
        edge_traces.append(go.Scatter(
            x=[x0, x1, None], y=[y0, y1, None],
            mode="lines",
            line=dict(width=ew, color=ec),
            hoverinfo="none", showlegend=False,
        ))
        dx, dy = x1 - x0, y1 - y0
        dist = math.hypot(dx, dy) or 1
        shrink = 0.18
        annotations.append(dict(
            x=x1 - dx * shrink, y=y1 - dy * shrink,
            ax=x0, ay=y0,
            xref="x", yref="y", axref="x", ayref="y",
            showarrow=True, arrowhead=2, arrowsize=1.2,
            arrowwidth=1.5, arrowcolor=ec,
        ))

    # Node traces — split into 3 groups for legend
    def make_node_trace(node_list, name, symbol):
        if not node_list:
            return None
        sizes = [max(20, min(50, 20 + (in_deg[n] + out_deg[n]) * 3)) for n in node_list]
        colors = [node_color(n) for n in node_list]
        return go.Scatter(
            x=[pos[n][0] for n in node_list],
            y=[pos[n][1] for n in node_list],
            mode="markers+text",
            marker=dict(symbol=symbol, size=sizes, color=colors,
                        line=dict(width=2, color="#475569")),
            text=node_list,
            textposition="top center",
            textfont=dict(size=10, color="#1E293B"),
            hovertemplate=(
                "<b>%{customdata[0]}</b><br>In: %{customdata[1]}  Out: %{customdata[2]}<extra></extra>"
            ),
            customdata=[[n, in_deg[n], out_deg[n]] for n in node_list],
            name=name, showlegend=True,
        )

    traces = [t for t in [
        *edge_traces,
        make_node_trace(list(source_nodes), "Base tables", "circle"),
        make_node_trace(list(dependent_nodes), "CTEs", "square"),
    ] if t is not None]

    x_vals = [p[0] for p in pos.values()]
    y_vals = [p[1] for p in pos.values()]

    fig = go.Figure(data=traces, layout=go.Layout(
        title=dict(
            text=f"Dependency Graph · {len(G.nodes)} nodes · "
                 + (f"{len(matched_nodes)} matched" if matched_nodes else "all shown"),
            font=dict(size=15), x=0.5,
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
# MAIN
# ═══════════════════════════════════════════════════════════════

query = st.text_area("Paste your SQL query here", height=260)

if not query:
    st.stop()

try:
    parsed = parse_query(query)
    ctes = extract_ctes(parsed)
    deps = build_dependencies(ctes)
    # ✅ ADD THIS BLOCK HERE
    cte_sql_map = {
        name: expr.sql(pretty=True)
        for name, expr in ctes.items()
    }
    lineage, final_lineage = build_lineage(ctes, parsed)
    duplicate_ctes, duplicate_notes = find_duplicate_ctes(lineage, cte_sql_map)

except Exception as e:
    st.error("Error parsing SQL query")
    st.exception(e)
    st.stop()

# ── Build graph once ─────────────────────────────────────────
G = create_graph(deps)

# ── All available columns (for autocomplete) ─────────────────
all_columns: list[str] = sorted({
    col.get("output", "")
    for cols in lineage.values()
    for col in cols
    if col.get("output")
})

# ═══════════════════════════════════════════════════════════════
# SEARCH BAR  (prominent, above everything)
# ═══════════════════════════════════════════════════════════════

st.markdown("---")
st.markdown("### 🔍 Column Search")
search_col, clear_col = st.columns([5, 1])

with search_col:
    column_search = st.selectbox(
        "Search for a column to highlight its CTEs and dependencies",
        options=[""] + all_columns,
        format_func=lambda x: "— show all —" if x == "" else x,
        index=0,
        label_visibility="collapsed",
    )

with clear_col:
    if st.button("✕ Clear", use_container_width=True):
        column_search = ""

# Derive highlight sets
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

st.markdown("---")

# ═══════════════════════════════════════════════════════════════
# SUMMARY METRICS
# ═══════════════════════════════════════════════════════════════

st.markdown("### 📊 Query Summary")
c1, c2, c3, c4 = st.columns(4)
c1.metric("CTEs", len(ctes))
c2.metric("Dependencies", sum(len(v) for v in deps.values()))
c3.metric("Final Columns", len(final_lineage))
c4.metric("Matched CTEs", len(matched_ctes) if column_search else "—")

try:
    execution_order = list(nx.topological_sort(G))
    st.markdown("**Execution Flow:**")
    # Highlight matched nodes in the flow string
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
    st.warning("⚠️ Could not determine execution order (possible cycle)")

st.markdown("---")

# ═══════════════════════════════════════════════════════════════
# TABS
# ═══════════════════════════════════════════════════════════════

tab1, tab2, tab3 , tab4, tab5 ,tab6, tab7 = st.tabs(
    ["📌 CTE Breakdown", "🔗 Dependency Graph", "🧬 Column Lineage","🔗 Column Paths", "🧭 Column Dependency","Getting Number Of rows for Each CTE (Q)", "🛠 Debugger"])

# ── TAB 1: CTE Breakdown ────────────────────────────────────
with tab1:
    st.subheader("CTE Step-by-Step View")

    if not ctes:
        st.info("No CTEs found in the query.")
    else:
        show_all = st.toggle(
            "Show all CTEs",
            value=not bool(column_search),
            help="When a column is searched, only matched CTEs are shown if OFF.",
        )

        for i, (name, expr) in enumerate(ctes.items(), start=1):
            is_matched  = name in matched_ctes
            in_subgraph = name in subgraph_nodes

            # ✅ UPDATED LOGIC
            if column_search:
                if show_all:
                    pass
                else:
                    if not is_matched:
                        continue

            # Badge
            if is_matched:
                badge = "🟡 **Column match**"
            elif in_subgraph and column_search:
                badge = "🔵 Related dependency"
            else:
                badge = ""

            label = f"Step {i}: `{name}`  {badge}"

            with st.expander(label, expanded=is_matched):
                st.code(expr.sql(), language="sql")

                if is_matched and column_search:
                    matching_cols = [
                        col for col in lineage.get(name, [])
                        if column_search.lower() in col.get("output", "").lower()
                        or any(column_search.lower() in str(s).lower()
                               for s in col.get("sources", []))
                    ]
                    if matching_cols:
                        st.markdown("**Matched columns:**")
                        for col in matching_cols:
                            st.markdown(
                                f"- `{col['output']}` ← {col['sources']}"
                            )

# ── TAB 2: Dependency Graph ─────────────────────────────────
with tab2:
    st.subheader("Dependency Visualization")

    if not deps:
        st.info("No dependencies found.")
    else:
        graph_mode = st.radio(
            "Graph type", ["Static (Plotly)", "Interactive (pyvis)"],
            horizontal=True,
        )

        if column_search and matched_ctes:
            st.info(
                f"🟡 **Yellow** = CTEs containing `{column_search}`  ·  "
                "Normal colour = ancestor/descendant  ·  "
                "🩶 Grey = unrelated"
            )

        if duplicate_ctes:
            st.warning(
                "🟠 **Orange** = duplicate-risk CTEs or repeated columns detected. "
                "These nodes are also highlighted in the debugger tab."
            )

        if graph_mode == "Static (Plotly)":
            fig = draw_highlighted_graph(deps, subgraph_nodes, matched_ctes, duplicate_ctes)
            st.plotly_chart(fig, use_container_width=True)

        else:
            # For pyvis, pass highlight metadata via node colours directly
            from utils.graph import interactive_graph
            html_path = interactive_graph(
                deps,
                ctes=ctes,
                cte_sql_map=cte_sql_map,       # 👈 ADD THIS
                search_column=column_search,   # 👈 ADD THIS
                highlight_nodes=subgraph_nodes,
                matched_nodes=matched_ctes,
                duplicate_nodes=duplicate_ctes,
            )
            with open(html_path, "r", encoding="utf-8") as f:
                st.components.v1.html(f.read(), height=680, scrolling=False)

# ── TAB 3: Column Lineage ───────────────────────────────────
with tab3:
    st.subheader("Column-Level Lineage")

    if not lineage:
        st.info("No lineage information available.")
    else:
        # Filter to matched CTEs when searching
        display_lineage = (
            {k: v for k, v in lineage.items() if k in subgraph_nodes}
            if column_search and subgraph_nodes
            else lineage
        )

        for cte, cols in display_lineage.items():
            is_matched = cte in matched_ctes
            header_prefix = "🟡" if is_matched else "🔹"
            st.markdown(f"### {header_prefix} {cte}")

            if not cols:
                st.write("No columns detected")
            else:
                for col in cols:
                    output = col["output"]
                    sources = col["sources"]
                    # Highlight the matched column
                    if column_search and column_search.lower() in output.lower():
                        st.markdown(
                            f"> 🟡 **`{output}`** ← `{sources}`"
                        )
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
with tab4:
    st.subheader("🔗 Column Path Tracing")

    if not column_search:
        st.info("Select a column to trace its path")
    else:
        col_graph = build_column_graph(lineage)

        # ✅ Detect final outputs dynamically
        final_cte = list(lineage.keys())[-1]

        final_outputs = {
            f"{final_cte}.{col['output']}".lower()
            for col in final_lineage
        }

        paths = trace_column_paths(
            col_graph,
            column_search,
            final_outputs
        )

        if not paths:
            st.warning("No paths found")
        else:
            for i, path in enumerate(paths, 1):
                st.markdown(f"### 🛣️ Path {i}")

                formatted = []
                seen_ctes = set()

                for node in path:
                    col = node.split(".")[-1]
                    cte = node.split(".")[0]

                    # Highlight searched column
                    if col.lower() == column_search.lower():
                        formatted.append(f"🟡 **`{node}`**")
                    else:
                        formatted.append(f"`{node}`")

                    # ✅ Show SQL only once per CTE
                    if cte not in seen_ctes:
                        seen_ctes.add(cte)

                        if cte in cte_sql_map:
                            with st.expander(f"📄 SQL for `{cte}`"):
                                sql = cte_sql_map[cte]

                                # Highlight column
                                sql = highlight_column(sql, column_search)

                                st.code(sql, language="sql")

                                # 🔥 Duplicate risk detection
                                risk = detect_duplicate_risk(sql)
                                if risk:
                                    st.warning(risk)

                                joins = extract_joins(sql)
                                if joins:
                                    st.markdown("**🔗 Joins:**")
                                    for j in joins:
                                        st.code(j, language="sql")

                st.markdown(" → ".join(formatted))

                # 🔁 Transformation detection
                st.markdown("#### 🔄 Transformations")
                for j in range(len(path) - 1):
                    src = path[j].split(".")[-1]
                    tgt = path[j + 1].split(".")[-1]

                    if src != tgt:
                        st.markdown(f"⚠️ `{src}` → `{tgt}`")

                st.markdown("---")
with tab5:
    st.subheader("🧭 Column Dependency Explorer")

    if not column_search:
        st.info("Select a column to explore dependencies")
    else:
        col_graph = build_column_graph(lineage)
        rev_graph = build_reverse_graph(col_graph)

        upstream, current, downstream = get_column_dependencies(
            col_graph, rev_graph, column_search
        )

        # ─────────────────────────────
        # 🔙 UPSTREAM
        # ─────────────────────────────
        st.markdown("### 🔙 Upstream")

        if not upstream:
            st.write("No upstream dependencies")
        else:
            for u in sorted(upstream):
                st.markdown(f"- `{u}`")

                cte = u.split(".")[0]
                if cte in cte_sql_map:
                    with st.expander(f"📄 SQL: `{cte}`"):
                        sql = highlight_column(cte_sql_map[cte], column_search)
                        st.code(sql, language="sql")

                        risk = detect_duplicate_risk(sql)
                        if risk:
                            st.warning(risk)

        # ─────────────────────────────
        # ➡️ CURRENT
        # ─────────────────────────────
        st.markdown("### ➡️ Current")

        for c in current:
            st.markdown(f"- 🟡 `{c}`")

            cte = c.split(".")[0]
            if cte in cte_sql_map:
                with st.expander(f"📄 SQL: `{cte}`"):
                    sql = highlight_column(cte_sql_map[cte], column_search)
                    st.code(sql, language="sql")

        # ─────────────────────────────
        # 🔜 DOWNSTREAM
        # ─────────────────────────────
        st.markdown("### 🔜 Downstream")

        if not downstream:
            st.write("No downstream dependencies")
        else:
            for d in sorted(downstream):
                st.markdown(f"- `{d}`")

                cte = d.split(".")[0]
                if cte in cte_sql_map:
                    with st.expander(f"📄 SQL: `{cte}`"):
                        sql = highlight_column(cte_sql_map[cte], column_search)
                        st.code(sql, language="sql")

                        risk = detect_duplicate_risk(sql)
                        if risk:
                            st.warning(risk)

with tab7:
    st.subheader("🛠 Debugger — packet your query columns and duplicate risk")

    if not column_search:
        st.info("Search a column in the left panel to inspect which CTEs contain it and where duplicate risk shows up.")
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
            st.success("No obvious duplicate-risk CTEs or repeated output columns detected.")

        st.markdown("---")
        st.markdown("### 🧠 Column debugger output")

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
                with st.expander(f"📄 Query SQL for `{cte}`"):
                    sql = highlight_column(cte_sql_map[cte], column_search)
                    st.code(sql, language="sql")
                    risk = detect_duplicate_risk(sql)
                    if risk:
                        st.warning(risk)
                    joins = extract_joins(cte_sql_map[cte])
                    if joins:
                        st.markdown("**Joins detected:**")
                        for j in joins:
                            st.code(j, language="sql")

    if duplicate_ctes:
        st.markdown("---")
        st.markdown("### 🔶 Interactive graph highlights duplicate risk in orange")
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

with tab6:
    st.set_page_config(page_title="CTE Row Counter", page_icon="📊", layout="wide")

    st.title("📊 CTE Row Counter")
    st.caption("Paste any SQL query → get a ready-to-run COUNT(*) query for every CTE")


    # ═══════════════════════════════════════════════════════════════
    # ROBUST CTE PARSER
    # Handles:
    #   ✓ WITH cte1 AS (...), cte2 AS (...) comma-separated
    #   ✓ Quoted names: "cte_name", [cte_name], `cte_name`
    #   ✓ WITH RECURSIVE
    #   ✓ Nested subqueries (any depth)
    #   ✓ Inline comments  --
    #   ✓ Block comments   /* */
    #   ✓ WITH not at position 0
    # ═══════════════════════════════════════════════════════════════

    def strip_comments(sql: str) -> str:
        result = []
        i = 0
        in_single = in_double = False
        while i < len(sql):
            c = sql[i]
            if c == "'" and not in_double:
                in_single = not in_single
                result.append(c); i += 1; continue
            if c == '"' and not in_single:
                in_double = not in_double
                result.append(c); i += 1; continue
            if in_single or in_double:
                result.append(c); i += 1; continue
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
        depth = 0; i = start
        in_single = in_double = False
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


    def extract_ctes(sql: str) -> dict:
        sql = strip_comments(sql)

        with_pattern = re.compile(r'\bWITH\b\s*(?:RECURSIVE\s+)?', re.IGNORECASE)
        with_match = with_pattern.search(sql)
        if not with_match:
            return {}

        pos = with_match.end()
        ctes = {}

        # Matches: plain_word, "quoted", [bracketed], `backtick`  followed by optional col list then AS (
        name_pat = re.compile(
            r'\s*(?:"([^"]+)"|`([^`]+)`|\[([^\]]+)\]|(\w+))\s*(?:\([^)]*\))?\s+AS\s*\(',
            re.IGNORECASE,
        )

        while pos < len(sql):
            # skip whitespace + commas
            while pos < len(sql) and sql[pos] in (' ', '\t', '\n', '\r', ','):
                pos += 1

            m = name_pat.match(sql, pos)
            if not m:
                break

            cte_name = m.group(1) or m.group(2) or m.group(3) or m.group(4)
            open_paren = m.end() - 1
            close_paren = find_matching_paren(sql, open_paren)
            if close_paren == -1:
                break

            ctes[cte_name] = sql[open_paren + 1:close_paren].strip()
            pos = close_paren + 1

            peek = sql[pos:].lstrip().upper()
            if any(peek.startswith(k) for k in ('SELECT', 'INSERT', 'UPDATE', 'DELETE', 'MERGE', '')):
                # peek starts with final query keyword → we're done
                if not peek or any(peek.startswith(k) for k in ('SELECT', 'INSERT', 'UPDATE', 'DELETE', 'MERGE')):
                    break

        return ctes


    # ═══════════════════════════════════════════════════════════════
    # COUNT QUERY BUILDER
    # ═══════════════════════════════════════════════════════════════

    def build_count_query(ctes: dict) -> str:
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


    # ═══════════════════════════════════════════════════════════════
    # UI
    # ═══════════════════════════════════════════════════════════════

    sql_input = st.text_area(
        "Paste your SQL query here",
        height=320,
        placeholder=(
            "WITH\n"
            "  cte1 AS (SELECT ...),\n"
            "  cte2 AS (SELECT ... FROM cte1)\n"
            "SELECT * FROM cte2;"
        ),
    )

    if not sql_input.strip():
        st.stop()

    ctes = extract_ctes(sql_input)

    if not ctes:
        st.error(
            "❌ No CTEs found. "
            "Make sure the query contains `WITH cte_name AS (...)`. "
            "Check for missing `WITH` keyword or completely empty CTE bodies."
        )
        with st.expander("🔍 Debug — view stripped SQL (comments removed)"):
            st.code(strip_comments(sql_input)[:3000], language="sql")
        st.stop()

    names = list(ctes.keys())
    st.success(f"✅ Found **{len(names)} CTE(s):** {', '.join(f'`{n}`' for n in names)}")

    count_query = build_count_query(ctes)

    st.markdown("### ▶ Run this query to get row counts")
    st.caption("Copy-paste into any SQL client — Snowflake, BigQuery, Postgres, Redshift, etc.")
    st.code(count_query, language="sql")

    st.download_button(
        "⬇ Download as .sql",
        data=count_query.encode(),
        file_name="cte_row_counts.sql",
        mime="text/plain",
    )