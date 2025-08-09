from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import db, Courier, Order

bp = Blueprint("couriers", __name__)

@bp.route("/orders", methods=["GET"])
@jwt_required()
def get_assigned_orders():
    identity = get_jwt_identity()
    courier_id = identity.get("id")
    orders = Order.query.filter_by(courier_id=courier_id).filter(Order.status.in_(["yeni", "teslim alındı"])).all()
    return jsonify([{
        "id": o.id,
        "external_id": o.external_id,
        "status": o.status,
        "total_amount": o.total_amount,
        "address": o.address
    } for o in orders])

@bp.route("/orders/<order_id>/pickup", methods=["POST"])
@jwt_required()
def pickup_order(order_id):
    identity = get_jwt_identity()
    courier_id = identity.get("id")
    order = Order.query.filter_by(id=order_id, courier_id=courier_id).first_or_404()
    if order.status != "yeni":
        return jsonify({"error": "Sipariş zaten teslim alınmış veya teslim edilmiş"}), 400
    order.status = "teslim alındı"
    courier = Courier.query.get(courier_id)
    courier.status = "teslimatta"
    db.session.commit()
    return jsonify({"message": "Sipariş teslim alındı"})

@bp.route("/orders/<order_id>/deliver", methods=["POST"])
@jwt_required()
def deliver_order(order_id):
    identity = get_jwt_identity()
    courier_id = identity.get("id")
    order = Order.query.filter_by(id=order_id, courier_id=courier_id).first_or_404()
    if order.status != "teslim alındı":
        return jsonify({"error": "Sipariş teslim alınmamış"}), 400
    order.status = "teslim edildi"
    courier = Courier.query.get(courier_id)
    courier.status = "boşta"
    db.session.commit()
    return jsonify({"message": "Sipariş teslim edildi"})

@bp.route("/status", methods=["POST"])
@jwt_required()
def update_status():
    identity = get_jwt_identity()
    courier_id = identity.get("id")
    data = request.json
    new_status = data.get("status")
    if new_status not in ["boşta", "molada", "teslimatta"]:
        return jsonify({"error": "Geçersiz durum"}), 400
    courier = Courier.query.get_or_404(courier_id)
    courier.status = new_status
    db.session.commit()
    return jsonify({"message": f"Durum {new_status} olarak güncellendi"})

@bp.route("/status", methods=["GET"])
@jwt_required()
def get_status():
    identity = get_jwt_identity()
    courier_id = identity.get("id")
    courier = Courier.query.get_or_404(courier_id)
    return jsonify({"status": courier.status})
