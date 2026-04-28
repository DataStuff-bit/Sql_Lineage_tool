from collections import defaultdict

# ─────────────────────────────────────────────
# Build forward column graph
# src → output
# ─────────────────────────────────────────────
def build_column_graph(lineage: dict):
    graph = defaultdict(set)

    for cte, cols in lineage.items():
        for col in cols:
            output = f"{cte}.{col['output']}".lower()
            sources = [str(s).lower() for s in col.get("sources", [])]

            for src in sources:
                graph[src].add(output)

    return graph


# ─────────────────────────────────────────────
# Reverse graph (for upstream)
# ─────────────────────────────────────────────
def build_reverse_graph(graph):
    reverse = defaultdict(set)
    for src, targets in graph.items():
        for tgt in targets:
            reverse[tgt].add(src)
    return reverse


# ─────────────────────────────────────────────
# Column path tracing
# ─────────────────────────────────────────────
def trace_column_paths(graph, target_column, final_outputs):
    target_column = target_column.lower()
    paths = []

    def is_match(node):
        return node.split(".")[-1].lower() == target_column

    # Filter only relevant nodes
    valid_nodes = {n for n in graph if is_match(n)}
    for targets in graph.values():
        for t in targets:
            if is_match(t):
                valid_nodes.add(t)

    # DFS with constraint
    def dfs(node, path, visited):
        if node in visited:
            return
        visited.add(node)

        # ✅ stop only if it's a FINAL output
        if node in final_outputs:
            paths.append(path.copy())
            return

        for nxt in graph.get(node, []):
            if is_match(nxt):   # 🔥 restrict to same column only
                dfs(nxt, path + [nxt], visited.copy())

    # start from base sources only
    for node in valid_nodes:
        if node not in graph:  # source node
            dfs(node, [node], set())

    return paths


# ─────────────────────────────────────────────
# Full dependency explorer
# ─────────────────────────────────────────────
def get_column_dependencies(graph, reverse_graph, column):
    column = column.lower()

    upstream = set()
    downstream = set()

    def is_match(node):
        return node.split(".")[-1].lower() == column

    matching_nodes = [n for n in reverse_graph if is_match(n)]

    # Upstream DFS
    def dfs_up(node):
        for parent in reverse_graph.get(node, []):
            if parent not in upstream:
                upstream.add(parent)
                dfs_up(parent)

    # Downstream DFS
    def dfs_down(node):
        for child in graph.get(node, []):
            if child not in downstream:
                downstream.add(child)
                dfs_down(child)

    for node in matching_nodes:
        dfs_up(node)
        dfs_down(node)

    return upstream, matching_nodes, downstream