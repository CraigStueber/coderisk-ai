from flask import Flask

app = Flask(__name__)


# SHOULD TRIGGER: Missing @login_required
@app.route("/admin")
def admin_panel():
    return "Welcome to admin panel"


# SHOULD TRIGGER: Missing auth decorator
@app.route("/users/<int:user_id>/delete", methods=["POST"])
def delete_user(user_id):
    return f"User {user_id} deleted"


# SHOULD NOT TRIGGER: Has @login_required
from flask_login import login_required


@app.route("/dashboard")
@login_required
def dashboard():
    return "Dashboard"


# SHOULD TRIGGER: Commented-out authorization check
@app.route("/sensitive-data")
def get_sensitive_data():
    # if not user.is_admin:
    #     raise Forbidden()
    return "Sensitive data here"


# FastAPI examples
from fastapi import FastAPI, Depends

app_api = FastAPI()


# SHOULD TRIGGER: Missing dependencies
@app_api.get("/users")
def list_users():
    return {"users": []}


# SHOULD NOT TRIGGER: Has Depends in signature
def get_current_user():
    return {"id": 1}


@app_api.get("/profile")
def get_profile(user=Depends(get_current_user)):
    return user


# SHOULD TRIGGER: No auth
@app_api.post("/admin/settings")
def update_settings():
    return {"status": "updated"}


# SHOULD TRIGGER: Commented check_permission
@app_api.delete("/records/{record_id}")
def delete_record(record_id: int):
    # check_permission("delete", current_user)
    return {"deleted": record_id}
