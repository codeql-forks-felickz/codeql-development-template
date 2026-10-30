import asyncpg
import asyncpg.connection
import asyncpg.pool
from asyncpg import Connection


async def create(conn: Connection, name: str):
    await conn.execute(f"INSERT INTO students (name) VALUES ('{name}')")  # $ Alert


async def create_module_annotation(conn: asyncpg.connection.Connection, name: str):
    await conn.fetch(f"SELECT * FROM students WHERE name = '{name}'")  # $ Alert


async def create_safe(conn: Connection, name: str):
    await conn.execute("INSERT INTO students (name) VALUES ($1)", name)


async def create_with_pool(pool: asyncpg.Pool, name: str):
    await pool.fetchrow(f"SELECT * FROM students WHERE name = '{name}'")  # $ Alert
    async with pool.acquire() as conn:
        await conn.fetchval(f"SELECT id FROM students WHERE name = '{name}'")  # $ Alert


async def create_with_pool_module_annotation(pool: asyncpg.pool.Pool, name: str):
    await pool.execute(f"INSERT INTO students (name) VALUES ('{name}')")  # $ Alert
