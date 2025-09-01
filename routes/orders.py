from flask import Blueprint, request, jsonify
from models import db, Order

bp = Blueprint("orders", __name__)

@bp.route("/", methods=["GET"])
def list_orders():
    orders = Order.query.all()
    return jsonify([{
        "id": o.id, "status": o.status, "total_amount": o.total_amount
    } for o in orders])

@bp.route("/<order_id>", methods=["PUT"])
def update_order(order_id):
    order = Order.query.get_or_404(order_id)
    data = request.json
    order.status = data.get("status", order.status)
    order.courier_id = data.get("courier_id", order.courier_id)
    db.session.commit()
    return jsonify({"message": "Order updated"})
