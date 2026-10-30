class Student:
    @classmethod
    async def create(cls, conn, name):
        pass

    @classmethod
    async def get(cls, conn, id):
        pass

    @classmethod
    async def get_many(cls, conn):
        pass


class Course:
    @classmethod
    async def create(cls, conn, title, description):
        pass

    @classmethod
    async def get(cls, conn, id):
        pass

    @classmethod
    async def get_many(cls, conn):
        pass


class Mark:
    @classmethod
    async def create(cls, conn, student_id, course_id, points):
        pass
