import tornado.template
import tornado.web
from tornado.template import Template

TMPL = "<html><body>Hello NAMEHERE</body></html>"


class MainHandler(tornado.web.RequestHandler):
    def get(self):  # $ Source[py/code-injection]
        name = self.get_argument("name", "")
        template_data = TMPL.replace("NAMEHERE", name)
        t = tornado.template.Template(template_data)  # $ Alert[py/code-injection]
        self.write(t.generate(name=name))


class KeywordHandler(tornado.web.RequestHandler):
    def get(self):  # $ Source[py/code-injection]
        name = self.get_argument("name", "")
        t = Template(template_string="Hello " + name)  # $ Alert[py/code-injection]
        self.write(t.generate())


class SafeHandler(tornado.web.RequestHandler):
    def get(self):
        name = self.get_argument("name", "")
        t = tornado.template.Template("Hello {{ name }}")
        self.write(t.generate(name=name))
