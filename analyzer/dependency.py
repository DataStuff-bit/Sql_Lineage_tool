import sqlglot
from collections import defaultdict

def build_dependencies(ctes):
    deps = defaultdict(list)

    for name, expr in ctes.items():
        for table in expr.find_all(sqlglot.exp.Table):
            if table.name in ctes:
                deps[name].append(table.name)

    return dict(deps)