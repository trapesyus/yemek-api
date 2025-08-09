from flask import Blueprint, request, jsonify
from models import db, Courier
from flask_jwt_extended import create_access_token
import datetime

bp = Blueprint("auth", __name__)

@bp.route("/login", methods=["POST"])
def login():
    data = request.json
    email = data.get("email")
    password = data.get("password")
    courier = Courier.query.filter_by(email=email).first()
    if courier and courier.check_password(password):
        expires = datetime.timedelta(days=1)
        access_token = create_access_token(identity={"id": courier.id, "email": courier.email}, expires_delta=expires)
        return jsonify(access_token=access_token)
    return jsonify({"error": "Geçersiz kullanıcı adı veya şifre"}), 401
