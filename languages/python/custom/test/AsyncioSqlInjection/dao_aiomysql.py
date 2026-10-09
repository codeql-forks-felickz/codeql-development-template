import aiomysql
import aiomysql.cursors
from aiomysql.connection import Connection
from aiomysql.sa import SAConnection


async def create(conn: Connection, name: str):
    q = ("INSERT INTO students (name) "
         "VALUES ('%(name)s')" % {"name": name})
    async with conn.cursor() as cur:
        # The sink is now modeled, but `codeql/python-all` does not propagate taint
        # from a dict literal through `%` string formatting.
        await cur.execute(q)  # $ MISSING: Alert
        await cur.execute("INSERT INTO students (name) VALUES ('%s')" % (name,))  # $ Alert


async def create_top_level_annotation(conn: aiomysql.Connection, name: str):
    cur = await conn.cursor()
    await cur.execute(query=f"INSERT INTO students (name) VALUES ('{name}')")  # $ Alert


async def create_safe(conn: Connection, name: str):
    async with conn.cursor() as cur:
        await cur.execute("INSERT INTO students (name) VALUES (%s)", (name,))


async def create_with_cursor(cur: aiomysql.Cursor, name: str):
    await cur.execute(f"INSERT INTO students (name) VALUES ('{name}')")  # $ Alert


async def create_with_cursor_module_annotation(cur: aiomysql.cursors.DictCursor, name: str):
    await cur.execute(f"INSERT INTO students (name) VALUES ('{name}')")  # $ Alert


async def create_with_pool(pool: aiomysql.Pool, name: str):
    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(f"INSERT INTO students (name) VALUES ('{name}')")  # $ Alert


async def create_sa(conn: SAConnection, name: str):
    await conn.execute(f"INSERT INTO students (name) VALUES ('{name}')")  # $ Alert


async def count_sa(conn: SAConnection, name: str):
    return await conn.scalar(f"SELECT count(*) FROM students WHERE name = '{name}'")  # $ Alert
