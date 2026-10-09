import jinja2
from flask import Flask, current_app, request, render_template_string, stream_template_string  # $ Source[py/template-injection] Source[py/code-injection]
from jinja2 import Environment, Template

app = Flask(__name__)


# Positional forms: already modeled by `codeql/python-all` (py/template-injection).
@app.route("/positional")
def positional():
    name = request.args.get("name")
    render_template_string("Hello " + name)  # $ Alert[py/template-injection]
    stream_template_string("Hello " + name)  # $ Alert[py/template-injection]
    Environment().from_string("Hello " + name)  # $ Alert[py/template-injection]
    jinja2.Environment(loader=jinja2.BaseLoader()).from_string("Hello " + name)  # $ Alert[py/template-injection]
    return Template("Hello " + name).render()  # $ Alert[py/template-injection]


# Keyword `source=` forms: added by template-injection.model.yml (py/code-injection).
@app.route("/keyword")
def keyword():
    name = request.args.get("name")
    render_template_string(source="Hello " + name)  # $ Alert[py/code-injection]
    stream_template_string(source="Hello " + name)  # $ Alert[py/code-injection]
    Environment().from_string(source="Hello " + name)  # $ Alert[py/code-injection]
    return Template(source="Hello " + name).render()  # $ Alert[py/code-injection]


# Flask application's Jinja2 environment: added by template-injection.model.yml.
@app.route("/jinja_env")
def jinja_env():
    name = request.args.get("name")
    app.jinja_env.from_string(source="Hello " + name)  # $ Alert[py/code-injection]
    current_app.jinja_env.from_string("Hello " + name)  # $ Alert[py/code-injection]
    return app.jinja_env.from_string("Hello " + name).render()  # $ Alert[py/code-injection]


# User input passed only as template context, not template source: safe.
@app.route("/safe")
def safe():
    name = request.args.get("name")
    render_template_string("Hello {{ n }}", n=name)
    stream_template_string(source="Hello {{ n }}", n=name)
    Environment().from_string("Hello {{ n }}").render(n=name)
    Template(source="Hello {{ n }}").render(n=name)
    return app.jinja_env.from_string("Hello {{ n }}").render(n=name)
