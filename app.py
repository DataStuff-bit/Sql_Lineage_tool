import streamlit as st
import re

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