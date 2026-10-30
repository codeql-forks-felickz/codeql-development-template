from flask import Flask

# GOOD: framework secrets in test directories are not reported
app = Flask(__name__)
app.secret_key = "testing"
