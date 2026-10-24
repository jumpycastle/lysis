import psycopg2, os

_conn = psycopg2.connect(os.environ["DATABASE_URL"])


def query(sql, params=()):
    with _conn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall() if cur.description else None
