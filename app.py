import os

from flask import Flask, render_template
from flask_security import SQLAlchemySessionUserDatastore, Security, login_user, logout_user
from flask_security import current_user, auth_required, login_required, roles_required, roles_accepted

from models import *


app = Flask(__name__)


app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///./model.db"

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", 
                                          "hbivnfdisbvljobfgjoihfhrugubdfsbery89w34yt5898he")
app.config["SECURITY_PASSWORD_SALT"] = os.environ.get("SECURITY_PASSWORD_SALT",
                                                       "hbivnfdisbvljobfgjoihfhrugubdfsbery89w34yt5898he")

# authenticatin paramter for url
app.config["SECURITY_TOKEN_AUTHENTICATION_KEY"] = "auth_key" # Default: auth_token
# in postman add the key as auth_key and value as the token , this should be in the url
app.config["SECURITY_TOKEN_AUTHENTICATION_HEADER"] = "Authentication-Token" # Default: Authentication-Token"
# in postman add the key as Authentication-Token and value as the token
# app.config[]

db.init_app(app)

user_datastore = SQLAlchemySessionUserDatastore(db.session, User, Role) # Not SQLAlchemyUserDatastore
app.security = Security(app, user_datastore)
with app.app_context():
    db.create_all()



@app.route('/')
def index():
    return render_template("index.html")


@app.route('/create-user/<string:username>/<string:role>')
def create_user(username, role):
    
    # Create and save the user
    app.security.datastore.create_user(username=username)
    db.session.commit()

    user = db.session.query(User).filter_by(username=username).first()
    role_user = db.session.query(Role).filter_by(name=role).first()

    role = RolesUsers(user_id=user.id, role_id=role_user.id)
    db.session.add(role)
    db.session.commit()

    return username


@app.route('/create-role/<string:role>')
def create_role(role):

    app.security.datastore.create_role(name=role)
    db.session.commit()

    return "Role Created Successfully"


@app.route("/get-roles")
def get_roles():
    return [x.name for x in db.session.query(Role).all()]


@app.route("/get-users")
def get_users():
    return [{"username": user.username,
             "id": user.id,
             "role": [role.name for role in user.roles]} for user in db.session.query(User).all()]


@app.route('/signin/<string:username>')
def signin(username):

    user = db.session.query(User).filter_by(username=username).first()
    result = login_user(user) # return True if able to signin the user else False

    return f"{user.username} signed in!" if result else "Failed to signin!"


@app.route('/get-user-details')
@login_required #Only after the route otherwise wont work
def get_user_details():
    return {"username": current_user.username,
             "id": current_user.id,
             "role": [role.name for role in current_user.roles]}


@app.route('/get-authenticated-data')
@auth_required('token')
# to allow admin and user to access the route
@roles_required('admin')
def get_authenticated_data():
    return {"username": current_user.username,
             "id": current_user.id,
             "role": [role.name for role in current_user.roles],
             "message": "Only can access if you pass token"}



@app.route('/multiple-roles')
@roles_accepted('admin', 'manager')
def multiple_roles():
    return {"username": current_user.username,
             "id": current_user.id,
             "role": [role.name for role in current_user.roles],
             "message": "Only can access if you are a user or admin"}

@app.route('/get-user-token')
def get_user_token():
    return {"token": current_user.get_auth_token()}


@app.route('/user-role-data')
@roles_required('user')
def user_role_date():
    return {"username": current_user.username,
             "id": current_user.id,
             "role": [role.name for role in current_user.roles],
             "message": "Only can access if you are a user"}


if __name__ == "__main__":
    app.run(debug=True,port=5003)