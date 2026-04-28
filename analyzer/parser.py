import sqlglot

def parse_query(query):
    return sqlglot.parse_one(query)