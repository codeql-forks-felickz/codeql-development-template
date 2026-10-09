import aiomysql
import aiopg
import asyncpg
from aiohttp import web

import dao_aiomysql
import dao_aiopg
import dao_asyncpg


async def init_db(app: web.Application):
    # Pools are stored in the application mapping, so API graphs cannot follow
    # them back to `create_pool` once they are read out in a request handler.
    app["pg"] = await aiopg.create_pool("dbname=school")
    app["mysql"] = await aiomysql.create_pool(db="school")
    app["asyncpg"] = await asyncpg.create_pool("postgresql:///school")


async def aiopg_students(request: web.Request):  # $ Source
    data = await request.post()
    name = data["name"]

    # Already modeled upstream: connection obtained directly from `aiopg.create_pool`.
    pool = await aiopg.create_pool("dbname=school")
    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute("INSERT INTO students (name) VALUES ('%s')" % name)  # $ Alert

    async with request.app["pg"].acquire() as conn:
        await dao_aiopg.create(conn, name)
        await dao_aiopg.create_top_level_annotation(conn, name)
        await dao_aiopg.create_awaited_cursor(conn, name)
        await dao_aiopg.create_safe(conn, name)
        async with conn.cursor() as cur:
            await dao_aiopg.create_with_cursor(cur, name)
            await dao_aiopg.create_with_cursor_module_annotation(cur, name)
    await dao_aiopg.create_with_pool(request.app["pg"], name)
    await dao_aiopg.create_with_pool_cursor(request.app["pg"], name)
    await dao_aiopg.create_sa(request.app["pg_sa"], name)
    await dao_aiopg.count_sa(request.app["pg_sa"], name)
    return web.Response(text="ok")


async def aiomysql_students(request: web.Request):  # $ Source
    data = await request.post()
    name = data["name"]

    # Already modeled upstream: connection obtained directly from `aiomysql.connect`.
    conn = await aiomysql.connect(db="school")
    async with conn.cursor() as cur:
        await cur.execute("INSERT INTO students (name) VALUES ('%s')" % name)  # $ Alert

    async with request.app["mysql"].acquire() as conn:
        await dao_aiomysql.create(conn, name)
        await dao_aiomysql.create_top_level_annotation(conn, name)
        await dao_aiomysql.create_safe(conn, name)
        async with conn.cursor() as cur:
            await dao_aiomysql.create_with_cursor(cur, name)
            await dao_aiomysql.create_with_cursor_module_annotation(cur, name)
    await dao_aiomysql.create_with_pool(request.app["mysql"], name)
    await dao_aiomysql.create_sa(request.app["mysql_sa"], name)
    await dao_aiomysql.count_sa(request.app["mysql_sa"], name)
    return web.Response(text="ok")


async def asyncpg_students(request: web.Request):  # $ Source
    data = await request.post()
    name = data["name"]

    # Already modeled upstream: connection obtained directly from `asyncpg.connect`.
    conn = await asyncpg.connect("postgresql:///school")
    await conn.execute("INSERT INTO students (name) VALUES ('%s')" % name)  # $ Alert

    async with request.app["asyncpg"].acquire() as conn:
        await dao_asyncpg.create(conn, name)
        await dao_asyncpg.create_module_annotation(conn, name)
        await dao_asyncpg.create_safe(conn, name)
    await dao_asyncpg.create_with_pool(request.app["asyncpg"], name)
    await dao_asyncpg.create_with_pool_module_annotation(request.app["asyncpg"], name)
    return web.Response(text="ok")


app = web.Application()
app.on_startup.append(init_db)
app.router.add_route("POST", "/aiopg/students", aiopg_students)
app.router.add_route("POST", "/aiomysql/students", aiomysql_students)
app.router.add_route("POST", "/asyncpg/students", asyncpg_students)
