from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)
DATABASE = "app.db"

# DB bağlantısı
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# Tablo oluşturma
def init_db():
    with get_db() as db:
        db.execute("""
        CREATE TABLE IF NOT EXISTS courier (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            phone TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('admin', 'courier'))
        )
        """)
        db.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vendor_id TEXT NOT NULL,
            product_name TEXT NOT NULL,
            quantity INTEGER NOT NULL,
            status TEXT NOT NULL
        )
        """)

init_db()

# ---------- Kurye Routes ----------

@app.route("/couriers", methods=["GET"])
def list_couriers():
    db = get_db()
    couriers = db.execute("SELECT * FROM courier").fetchall()
    return jsonify([dict(row) for row in couriers])

@app.route("/couriers", methods=["POST"])
def add_courier():
    data = request.json
    name = data.get("name")
    phone = data.get("phone")
    role = data.get("role", "courier")  # Varsayılan olarak courier
    
    db = get_db()
    db.execute("INSERT INTO courier (name, phone, role) VALUES (?, ?, ?)",
               (name, phone, role))
    db.commit()
    return jsonify({"message": "Kurye eklendi"}), 201

@app.route("/couriers/<int:courier_id>", methods=["PUT"])
def update_courier(courier_id):
    data = request.json
    name = data.get("name")
    phone = data.get("phone")
    role = data.get("role")
    
    db = get_db()
    db.execute("UPDATE courier SET name=?, phone=?, role=? WHERE id=?",
               (name, phone, role, courier_id))
    db.commit()
    return jsonify({"message": "Kurye güncellendi"})

@app.route("/couriers/<int:courier_id>", methods=["DELETE"])
def delete_courier(courier_id):
    db = get_db()
    db.execute("DELETE FROM courier WHERE id=?", (courier_id,))
    db.commit()
    return jsonify({"message": "Kurye silindi"})

# ---------- Yemek Sepeti Routes ----------

@app.route("/orders", methods=["GET"])
def list_orders():
    db = get_db()
    orders = db.execute("SELECT * FROM orders").fetchall()
    return jsonify([dict(row) for row in orders])

@app.route("/orders", methods=["POST"])
def add_order():
    data = request.json
    vendor_id = data.get("vendor_id")
    product_name = data.get("product_name")
    quantity = data.get("quantity")
    status = data.get("status", "pending")
    
    db = get_db()
    db.execute("""INSERT INTO orders (vendor_id, product_name, quantity, status) 
                  VALUES (?, ?, ?, ?)""",
               (vendor_id, product_name, quantity, status))
    db.commit()
    return jsonify({"message": "Sipariş eklendi"}), 201

@app.route("/orders/<int:order_id>", methods=["PUT"])
def update_order(order_id):
    data = request.json
    vendor_id = data.get("vendor_id")
    product_name = data.get("product_name")
    quantity = data.get("quantity")
    status = data.get("status")
    
    db = get_db()
    db.execute("""UPDATE orders SET vendor_id=?, product_name=?, quantity=?, status=? WHERE id=?""",
               (vendor_id, product_name, quantity, status, order_id))
    db.commit()
    return jsonify({"message": "Sipariş güncellendi"})

@app.route("/orders/<int:order_id>", methods=["DELETE"])
def delete_order(order_id):
    db = get_db()
    db.execute("DELETE FROM orders WHERE id=?", (order_id,))
    db.commit()
    return jsonify({"message": "Sipariş silindi"})

if __name__ == "__main__":
    app.run(debug=True)
