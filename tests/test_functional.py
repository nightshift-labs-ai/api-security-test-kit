"""Functional and data-format checks (response schema, field types, boundary values)."""
import re

import pytest

pytestmark = pytest.mark.functional
MONEY = re.compile(r"^\d+\.\d{2}$")


def test_products_schema_and_types(api):
    """What: GET /products returns a list of {id:int, name:str, price:"0.00" string, stock:int>=0}.
    Why: clients parse these fields; a wrong type or money format breaks checkout and reporting.
    Severity: Medium if broken
    Repro: curl -s http://127.0.0.1:8000/products
    """
    r = api.get("/products")
    assert r.status_code == 200 and isinstance(r.json(), list) and r.json()
    for p in r.json():
        assert set(p) == {"id", "name", "price", "stock"}
        assert isinstance(p["id"], int) and isinstance(p["name"], str)
        assert MONEY.match(p["price"]) and isinstance(p["stock"], int) and p["stock"] >= 0


def test_order_schema_and_types(api):
    """What: GET /orders/1 as owner returns the documented order shape with money as 2-decimal strings.
    Why: schema drift silently breaks clients and finance exports.
    Severity: Medium if broken
    Repro: curl -s -H 'Authorization: Bearer alice-token' http://127.0.0.1:8000/orders/1
    """
    o = api.get("/orders/1", as_user="alice").json()
    assert {"id", "user_id", "items", "coupon", "subtotal", "discount", "total", "status"} <= set(o)
    assert o["user_id"] == 1 and o["status"] in {"pending", "paid", "shipped", "cancelled"}
    for k in ("subtotal", "discount", "total"):
        assert MONEY.match(o[k]), f"{k}={o[k]!r}"
    for it in o["items"]:
        assert isinstance(it["quantity"], int) and MONEY.match(it["unit_price"])


def test_order_total_without_coupon(api):
    """What: POST /orders 2 x mouse (19.99) with no coupon must total exactly 39.98 (control case).
    Why: proves the pricing bug (if any) is in the discount path, not basic arithmetic.
    Severity: High if broken
    Repro: curl -s -X POST -H 'Authorization: Bearer alice-token' -H 'Content-Type: application/json' -d '{"items":[{"product_id":3,"quantity":2}]}' http://127.0.0.1:8000/orders
    """
    r = api.post("/orders", as_user="alice", json={"items": [{"product_id": 3, "quantity": 2}]})
    assert r.status_code == 201 and r.json()["total"] == "39.98" and r.json()["discount"] == "0.00"


@pytest.mark.parametrize("qty", [-1, 0, 101, 2**31])
def test_order_quantity_boundaries_rejected(api, qty):
    """What: POST /orders with quantity outside 1..100 (negative, zero, 101, 2^31) must be rejected with 422.
    Why: negative quantities create negative totals (refund fraud); huge ones overflow stock and totals.
    Severity: High if broken
    Repro: curl -s -X POST -H 'Authorization: Bearer alice-token' -H 'Content-Type: application/json' -d '{"items":[{"product_id":1,"quantity":-1}]}' http://127.0.0.1:8000/orders
    """
    r = api.post("/orders", as_user="alice", json={"items": [{"product_id": 1, "quantity": qty}]})
    assert r.status_code == 422


@pytest.mark.parametrize("limit,expected", [(1, 200), (100, 200), (0, 422), (101, 422), (1000000, 422)])
def test_page_size_boundaries(api, limit, expected):
    """What: GET /products?limit=N accepts 1..100 and rejects 0, 101 and 1,000,000 with 422.
    Why: an unbounded page size lets one request dump the table and exhaust memory (API4:2023).
    Severity: Medium if broken
    Repro: curl -s -o /dev/null -w '%{http_code}' 'http://127.0.0.1:8000/products?limit=1000000'
    """
    r = api.get("/products", params={"limit": limit})
    assert r.status_code == expected
    if expected == 200:
        assert len(r.json()) <= limit


def test_unknown_product_and_coupon(api):
    """What: POST /orders with a missing product id -> 404; with an unknown coupon -> 400.
    Why: silent acceptance of bad input creates orders that cannot be fulfilled or are mispriced.
    Severity: Medium if broken
    Repro: curl -s -X POST -H 'Authorization: Bearer alice-token' -H 'Content-Type: application/json' -d '{"items":[{"product_id":1,"quantity":1}],"coupon":"FREE100"}' http://127.0.0.1:8000/orders
    """
    assert api.post("/orders", as_user="alice", json={"items": [{"product_id": 999, "quantity": 1}]}).status_code == 404
    r = api.post("/orders", as_user="alice", json={"items": [{"product_id": 1, "quantity": 1}], "coupon": "FREE100"})
    assert r.status_code == 400


def test_invalid_ids_and_tokens(api):
    """What: non-numeric order id -> 422, unknown id -> 404, malformed/unknown bearer token -> 401.
    Why: consistent error handling avoids stack traces and makes authorization decisions predictable.
    Severity: Low if broken
    Repro: curl -s -H 'Authorization: Bearer not-a-token' http://127.0.0.1:8000/orders/1
    """
    assert api.get("/orders/abc", as_user="alice").status_code == 422
    assert api.get("/orders/999999", as_user="alice").status_code == 404
    assert api.get("/orders/1", headers={"Authorization": "Bearer not-a-token"}).status_code == 401
    assert api.get("/orders/1", headers={"Authorization": "Basic YWxpY2U6eA=="}).status_code == 401


def test_successful_login_returns_token(api):
    """What: POST /login with alice's correct password returns a bearer token that works on /users/me.
    Why: positive control for the lockout test, so lockout is not "passing" because login is simply broken.
    Severity: High if broken
    Repro: curl -s -X POST -H 'Content-Type: application/json' -d '{"username":"alice","password":"alice-pass-1"}' http://127.0.0.1:8000/login
    """
    r = api.post("/login", json={"username": "alice", "password": "alice-pass-1"})
    assert r.status_code == 200
    tok = r.json()["token"]
    assert api.get("/users/me", headers={"Authorization": f"Bearer {tok}"}).json()["username"] == "alice"
