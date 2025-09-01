from flask import Blueprint, request, jsonify
from models import db, Order

bp = Blueprint("webhooks", __name__)

@bp.route("/yemeksepeti", methods=["POST"])
def yemeksepeti_webhook():
    data = request.json
    if not data:
        return jsonify({"error": "No data"}), 400

    order = Order(
        external_id=data.get("order_id"),
        total_amount=data.get("total"),
        address=data.get("address"),
        payload=data
    )
    db.session.add(order)
    db.session.commit()
    return jsonify({"message": "Order received"}), 200
