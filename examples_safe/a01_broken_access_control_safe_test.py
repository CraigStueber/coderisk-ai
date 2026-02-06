"""
Safe version - Broken Access Control Fixed
All routes have proper authentication via @login_required decorator.
"""
from flask import Flask
from flask_login import login_required  # type: ignore

app = Flask(__name__)


# SAFE EVIDENCE: Has @login_required decorator
@app.route("/admin")
@login_required
def admin():
    return "ok"


# SAFE EVIDENCE: Has @login_required decorator
@app.route("/users/<int:user_id>/delete", methods=["POST"])
@login_required
def delete_user(user_id: int):
    return "deleted"


# SAFE EVIDENCE: Has @login_required decorator
@app.route("/dashboard")
@login_required
def dashboard():
    return "ok"


# SAFE EVIDENCE: Has @login_required decorator
@app.route("/sensitive-data")
@login_required
def sensitive_data():
    return "secret"
