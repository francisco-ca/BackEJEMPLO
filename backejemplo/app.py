import os
import re
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_script import Manager
from flask_migrate import Migrate, MigrateCommand
from flask_cors import CORS 
from flask_bcrypt import Bcrypt 
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from models import User, db

BASEDIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(BASEDIR, "test.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["DEBUG"] = True
app.config["ENV"] = "development"
app.config["JWT_SECRET_KEY"]= "encrypt"

db.init_app(app)
Migrate(app, db)
manager = Manager(app)
manager.add_command("db", MigrateCommand)
jwt = JWTManager(app)
bcrypt = Bcrypt(app)
CORS(app)

@app.route("/signup", methods=["POST"])
def signup():
    #expresion regular para validar email
    email_reg= "^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$"
    #expresion regular para valdiad contraseña
    password_reg= "^.*(?=.{8,})(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).*$"
    #Instancia un nuevo usuario
    user=User()
    #Checar email, el que recibo del front end
    if re.search(email_reg, request.json.get("email")):
        user.email= request.json.get("email")
    else:
        return jsonify({"msg": "Este correo no tiene un formato válido"}), 401
    #checar contraseña, la que recibo del front end
    if re.search(password_reg, request.json.get("password")):
        password_hash= bcrypt.generate_password_hash(request.json.get("password"))
        user.password = password_hash
    else:
        return jsonify({"msg":"El formato de la contraseña no es válido"}), 401
    
    user.username = request.json.get("username", None)
    user.name = request.json.get("name")

    db.session.add(user)
    db.session.commit()

    return jsonify({"success":True})

@app.route("/login", methods =["POST"])
def login():
    #Validar que el json o el body del front no este vacia
    if not request.is_json:
        return jsonify({"msg": "El body o contenido esta vacío"}), 400

    email = request.json.get("email", None)
    password=request.json.get("password", None)

    if not email:
        return jsonify({"msg":"Falta enviar el correo"}), 400
    if not password: 
        return jsonify({"msg":"Falta enviar la contraseña"}),400
    
    user=User.query.filter_by(email=email).first()  #.first() --> primera coincidencia

    if user is None:
        return jsonify({"msg":"Este usuario no está registrado"}),404

    if bcrypt.check_password_hash(user.password, password):
        access_token = create_access_token(identity=email)
        return jsonify({
            "access_token":access_token,
            "user": user.serialize(),
            "success":True
        }), 200
    else:
        return jsonify({"msg": "Contraseña erronea"}), 400

if __name__ == "__main__":
    manager.run()