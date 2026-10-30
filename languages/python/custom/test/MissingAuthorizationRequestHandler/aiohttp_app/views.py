from functools import wraps

from aiohttp.web import Application, HTTPFound, HTTPNotFound, HTTPUnauthorized, Request
from aiohttp_jinja2 import template
from aiohttp_session import get_session

from .dao import Course, Mark, Student


async def get_auth_user(request: Request):
    session = await get_session(request)
    return session.get("user_id")


def authorize(ensure_admin=False):
    def __decorator__(handler):
        @wraps(handler)
        async def __wrapper__(request: Request):
            user = await get_auth_user(request)
            if user is None:
                raise HTTPUnauthorized()
            return await handler(request)
        return __wrapper__
    return __decorator__


# ---- Vulnerable: writes without calling `authorize()` or checking the user ----

@template("students.jinja2")
async def students(request: Request):  # $ Alert[py/missing-authorization-request-handler]
    app = request.app
    if request.method == "POST":
        data = await request.post()
        async with app["db"].acquire() as conn:
            await Student.create(conn, data["name"])
    async with app["db"].acquire() as conn:
        students = await Student.get_many(conn)
    return {"students": students}


@template("courses.jinja2")
async def courses(request: Request):  # $ Alert[py/missing-authorization-request-handler]
    app = request.app
    if request.method == "POST":
        data = await request.post()
        async with app["db"].acquire() as conn:
            await Course.create(conn, data["title"], data["description"])
    async with app["db"].acquire() as conn:
        courses = await Course.get_many(conn)
    return {"courses": courses}


@template("evaluate.jinja2")
async def evaluate(request: Request):  # $ Alert[py/missing-authorization-request-handler]
    app = request.app
    student_id = int(request.match_info["student_id"])
    course_id = int(request.match_info["course_id"])
    data = await request.post()
    async with app["db"].acquire() as conn:
        student = await Student.get(conn, student_id)
        course = await Course.get(conn, course_id)
        if not student or not course:
            raise HTTPNotFound()
        await Mark.create(conn, student_id, course_id, data["points"])
    raise HTTPFound(f"/courses/{course_id}")


# ---- Safe: authorization enforced ----

@authorize()
@template("students.jinja2")
async def students_authorized(request: Request):
    app = request.app
    data = await request.post()
    async with app["db"].acquire() as conn:
        await Student.create(conn, data["name"])
    raise HTTPFound("/students/")


@template("evaluate.jinja2")
async def evaluate_checks_user(request: Request):
    auth_user = await get_auth_user(request)
    if auth_user is None:
        raise HTTPUnauthorized()
    app = request.app
    data = await request.post()
    async with app["db"].acquire() as conn:
        await Mark.create(conn, 1, 2, data["points"])
    raise HTTPFound("/courses/2")


# ---- Safe: read-only ----

@template("student.jinja2")
async def student(request: Request):
    app = request.app
    student_id = int(request.match_info["id"])
    async with app["db"].acquire() as conn:
        student = await Student.get(conn, student_id)
    return {"student": student}


def setup_routes(app: Application):
    app.router.add_route("GET", r"/students/", students)
    app.router.add_route("POST", r"/students/", students)
    app.router.add_route("POST", r"/courses/", courses)
    app.router.add_route("POST", r"/students/{student_id:\d+}/evaluate/{course_id:\d+}", evaluate)
    app.router.add_route("POST", r"/safe/students/", students_authorized)
    app.router.add_route("POST", r"/safe/evaluate", evaluate_checks_user)
    app.router.add_route("GET", r"/students/{id:\d+}", student)
