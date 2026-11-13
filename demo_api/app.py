"""Demo "shop" API with DELIBERATELY SEEDED flaws, for a testing portfolio sample.

Never deploy this. It exists only so the test suite has something to find.
Every seeded flaw is switched off when the environment variable DEMO_FIXED=1.

Seeded flaws (vulnerable mode):
  (a) BOLA/IDOR        GET  /orders/{id}       returns other users' orders
  (b) BFLA             GET  /admin/users, POST /admin/products  callable by normal users
  (c) Mass assignment  PATCH /users/me         accepts "role"
  (d) SQL injection    GET  /products?search=  string-built SQL
  (e) Data exposure    user objects include password_hash
  (f) Data accuracy    POST /orders            coupon discount applied twice (float math)
  (g) No lockout       POST /login             unlimited password guesses

Run:  uvicorn demo_api.app:app --host 127.0.0.1 --port 8000
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
from typing import Optional

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Query
from pydantic import BaseModel, Field

COUPONS = {"SAVE10": 10}  # percent off the order subtotal (see docs/pricing-spec.md)
LOCKOUT_AFTER = 5
LOCKOUT_SECONDS = 900


def _hash(pw: str) -> str:  # demo only; real systems use argon2/bcrypt
    return hashlib.sha256(pw.encode()).hexdigest()


def _money(cents: int) -> str:
    return f"{cents // 100}.{cents % 100:02d}"


class OrderItemIn(BaseModel):
    product_id: int = Field(ge=1)
    quantity: int = Field(ge=1, le=100)


class OrderIn(BaseModel):
    items: list[OrderItemIn] = Field(min_length=1, max_length=50)
    coupon: Optional[str] = Field(default=None, max_length=32)


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


class ProductIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    price: str = Field(pattern=r"^\d{1,6}\.\d{2}$")
    stock: int = Field(ge=0, le=100000)


def create_app(fixed: Optional[bool] = None) -> FastAPI:
    if fixed is None:
        fixed = os.environ.get("DEMO_FIXED", "0") == "1"

    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.row_factory = sqlite3.Row
    lock = threading.Lock()
    failures: dict[str, list[float]] = {}

    with lock:
        db.executescript(
            """
            CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, email TEXT,
                                display_name TEXT, role TEXT, password_hash TEXT, token TEXT UNIQUE);
            CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price_cents INTEGER, stock INTEGER);
            CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER, items TEXT, coupon TEXT,
                                 subtotal_cents INTEGER, discount_cents INTEGER, total_cents INTEGER,
                                 status TEXT);
            """
        )
        users = [
            (1, "alice", "alice@example.test", "Alice", "user", _hash("alice-pass-1"), "alice-token"),
            (2, "bob", "bob@example.test", "Bob", "user", _hash("bob-pass-2"), "bob-token"),
            (3, "admin", "admin@example.test", "Admin", "admin", _hash("admin-pass-3"), "admin-token"),
        ]
        db.executemany("INSERT INTO users VALUES (?,?,?,?,?,?,?)", users)
        db.executemany(
            "INSERT INTO products VALUES (?,?,?,?)",
            [(1, "USB-C cable", 999, 120), (2, "Mechanical keyboard", 4995, 15),
             (3, "Wireless mouse", 1999, 40), (4, "Laptop stand", 3450, 8)],
        )
        db.executemany(
            "INSERT INTO orders VALUES (?,?,?,?,?,?,?,?)",
            [(1, 1, json.dumps([{"product_id": 3, "name": "Wireless mouse", "quantity": 2, "unit_price": "19.99"}]),
              None, 3998, 0, 3998, "paid"),
             (2, 2, json.dumps([{"product_id": 2, "name": "Mechanical keyboard", "quantity": 1, "unit_price": "49.95"}]),
              None, 4995, 0, 4995, "shipped")],
        )
        db.commit()

    def q(sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        with lock:
            rows = db.execute(sql, params).fetchall()
            db.commit()
            return rows

    def user_out(row: sqlite3.Row) -> dict:
        d = dict(row)
        d.pop("token", None)
        if fixed:
            d.pop("password_hash", None)  # (e) fixed: explicit allow-list of public fields
        return d

    def order_out(row: sqlite3.Row) -> dict:
        return {
            "id": row["id"], "user_id": row["user_id"], "items": json.loads(row["items"]),
            "coupon": row["coupon"], "subtotal": _money(row["subtotal_cents"]),
            "discount": _money(row["discount_cents"]), "total": _money(row["total_cents"]),
            "status": row["status"],
        }

    def current_user(authorization: Optional[str] = Header(default=None)) -> sqlite3.Row:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(401, "missing bearer token", headers={"WWW-Authenticate": "Bearer"})
        rows = q("SELECT * FROM users WHERE token = ?", (authorization[7:].strip(),))
        if not rows:
            raise HTTPException(401, "invalid token", headers={"WWW-Authenticate": "Bearer"})
        return rows[0]

    def require_admin(user: sqlite3.Row = Depends(current_user)) -> sqlite3.Row:
        if fixed and user["role"] != "admin":  # (b) vulnerable mode skips the role check
            raise HTTPException(403, "admin role required")
        return user

    app = FastAPI(title="Demo Shop API (seeded flaws)", version="1.0",
                  description=f"mode={'fixed' if fixed else 'vulnerable'}")
    app.state.fixed = fixed

    @app.get("/health")
    def health():
        return {"status": "ok", "mode": "fixed" if fixed else "vulnerable"}

    @app.post("/login")
    def login(body: LoginIn):
        now = time.time()
        if fixed:  # (g) fixed: lock the account after 5 failures in 15 minutes
            recent = [t for t in failures.get(body.username, []) if now - t < LOCKOUT_SECONDS]
            failures[body.username] = recent
            if len(recent) >= LOCKOUT_AFTER:
                raise HTTPException(429, "too many failed attempts; try again later",
                                    headers={"Retry-After": str(LOCKOUT_SECONDS)})
        rows = q("SELECT * FROM users WHERE username = ?", (body.username,))
        if not rows or rows[0]["password_hash"] != _hash(body.password):
            failures.setdefault(body.username, []).append(now)
            raise HTTPException(401, "invalid credentials")
        failures.pop(body.username, None)
        return {"token": rows[0]["token"], "token_type": "bearer"}

    @app.get("/users/me")
    def me(user: sqlite3.Row = Depends(current_user)):
        return user_out(user)

    @app.patch("/users/me")
    def update_me(body: dict = Body(...), user: sqlite3.Row = Depends(current_user)):
        allowed = {"email", "display_name"} if fixed else {"email", "display_name", "role"}  # (c)
        bad = sorted(set(body) - allowed)
        if fixed and bad:
            raise HTTPException(422, f"fields not allowed: {', '.join(bad)}")
        for key in allowed & set(body):
            if not isinstance(body[key], str) or not (1 <= len(body[key]) <= 100):
                raise HTTPException(422, f"{key} must be a 1-100 character string")
            q(f"UPDATE users SET {key} = ? WHERE id = ?", (body[key], user["id"]))  # key from allow-list
        return user_out(q("SELECT * FROM users WHERE id = ?", (user["id"],))[0])

    @app.get("/products")
    def products(search: str = Query(default="", max_length=100), limit: int = Query(default=20, ge=1, le=100)):
        if fixed:  # (d) fixed: parameterised query
            rows = q("SELECT id, name, price_cents, stock FROM products WHERE name LIKE ? ORDER BY id LIMIT ?",
                     (f"%{search}%", limit))
        else:
            sql = ("SELECT id, name, price_cents, stock FROM products "
                   f"WHERE name LIKE '%{search}%' ORDER BY id LIMIT {limit}")
            try:
                rows = q(sql)
            except sqlite3.Error as exc:
                raise HTTPException(500, f"database error: {exc}")
        return [{"id": r["id"], "name": r["name"], "price": _money(int(r["price_cents"])), "stock": r["stock"]}
                for r in rows]

    @app.get("/orders")
    def list_orders(limit: int = Query(default=20, ge=1, le=100), user: sqlite3.Row = Depends(current_user)):
        rows = q("SELECT * FROM orders WHERE user_id = ? ORDER BY id LIMIT ?", (user["id"], limit))
        return [order_out(r) for r in rows]

    @app.get("/orders/{order_id}")
    def get_order(order_id: int, user: sqlite3.Row = Depends(current_user)):
        rows = q("SELECT * FROM orders WHERE id = ?", (order_id,))
        if not rows:
            raise HTTPException(404, "order not found")
        if fixed and rows[0]["user_id"] != user["id"] and user["role"] != "admin":  # (a)
            raise HTTPException(404, "order not found")  # 404, not 403: don't confirm the id exists
        return order_out(rows[0])

    @app.post("/orders", status_code=201)
    def create_order(body: OrderIn, user: sqlite3.Row = Depends(current_user)):
        if body.coupon is not None and body.coupon not in COUPONS:
            raise HTTPException(400, "unknown coupon")
        pct = COUPONS.get(body.coupon, 0)
        items, subtotal = [], 0
        for it in body.items:
            rows = q("SELECT * FROM products WHERE id = ?", (it.product_id,))
            if not rows:
                raise HTTPException(404, f"product {it.product_id} not found")
            p = rows[0]
            items.append({"product_id": p["id"], "name": p["name"], "quantity": it.quantity,
                          "unit_price": _money(p["price_cents"])})
            subtotal += p["price_cents"] * it.quantity
        if fixed:  # (f) fixed: integer cents, discount once on the subtotal, round half up
            discount = (subtotal * pct + 50) // 100
            total = subtotal - discount
        else:  # (f) bug: discount applied per line AND again on the order, in float
            t = 0.0
            for it, line in zip(body.items, items):
                t += float(line["unit_price"]) * it.quantity * (1 - pct / 100)
            t = t * (1 - pct / 100)
            total = int(round(t * 100))
            discount = subtotal - total
        cur_rows = q("INSERT INTO orders (user_id, items, coupon, subtotal_cents, discount_cents, total_cents, status)"
                     " VALUES (?,?,?,?,?,?, 'pending') RETURNING *",
                     (user["id"], json.dumps(items), body.coupon, subtotal, discount, total))
        return order_out(cur_rows[0])

    @app.get("/admin/users")
    def admin_users(admin: sqlite3.Row = Depends(require_admin)):
        return [user_out(r) for r in q("SELECT * FROM users ORDER BY id")]

    @app.post("/admin/products", status_code=201)
    def admin_create_product(body: ProductIn, admin: sqlite3.Row = Depends(require_admin)):
        cents = int(body.price.replace(".", ""))
        row = q("INSERT INTO products (name, price_cents, stock) VALUES (?,?,?) RETURNING *",
                (body.name, cents, body.stock))[0]
        return {"id": row["id"], "name": row["name"], "price": _money(row["price_cents"]), "stock": row["stock"]}

    return app


app = create_app()
