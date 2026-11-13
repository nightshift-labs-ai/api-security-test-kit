"""One test (or small group) per security / accuracy check, mapped to OWASP API Security Top 10 (2023)."""
from decimal import ROUND_HALF_UP, Decimal

import pytest

finding = pytest.mark.finding


@finding(id="F1", severity="High", owasp="API1:2023 Broken Object Level Authorization")
def test_bola_user_cannot_read_other_users_order(api):
    """What: bob requests GET /orders/1, which belongs to alice.
    Why: object IDs are sequential, so any customer could read every order (names, items, totals) by counting upward.
    Severity: High
    Repro: curl -s -H 'Authorization: Bearer bob-token' http://127.0.0.1:8000/orders/1
    """
    r = api.get("/orders/1", as_user="bob")
    assert r.status_code == 404, f"bob read alice's order: HTTP {r.status_code}"


@finding(id="F2", severity="Critical", owasp="API5:2023 Broken Function Level Authorization")
def test_bfla_normal_user_cannot_list_all_users(api):
    """What: alice (role=user) calls the admin-only GET /admin/users.
    Why: the admin route only checks that a token is valid, not the role, so every customer gets the full user list.
    Severity: Critical
    Repro: curl -s -H 'Authorization: Bearer alice-token' http://127.0.0.1:8000/admin/users
    """
    r = api.get("/admin/users", as_user="alice")
    assert r.status_code == 403, f"non-admin got HTTP {r.status_code} on /admin/users"


@finding(id="F2", severity="Critical", owasp="API5:2023 Broken Function Level Authorization")
def test_bfla_normal_user_cannot_create_products(api):
    """What: alice (role=user) calls the admin-only POST /admin/products.
    Why: write access to the catalog lets any customer add or price products.
    Severity: Critical
    Repro: curl -s -X POST -H 'Authorization: Bearer alice-token' -H 'Content-Type: application/json' -d '{"name":"x","price":"0.01","stock":1}' http://127.0.0.1:8000/admin/products
    """
    r = api.post("/admin/products", as_user="alice", json={"name": "x", "price": "0.01", "stock": 1})
    assert r.status_code == 403, f"non-admin got HTTP {r.status_code} on POST /admin/products"


@finding(id="F3", severity="Critical", owasp="API3:2023 Broken Object Property Level Authorization (mass assignment)")
def test_mass_assignment_cannot_set_role(api):
    """What: alice sends PATCH /users/me with {"role": "admin"}.
    Why: if the server copies every client field into the record, any user can promote themselves to admin.
    Severity: Critical
    Repro: curl -s -X PATCH -H 'Authorization: Bearer alice-token' -H 'Content-Type: application/json' -d '{"role":"admin"}' http://127.0.0.1:8000/users/me
    """
    api.patch("/users/me", as_user="alice", json={"role": "admin"})
    me = api.get("/users/me", as_user="alice").json()
    assert me["role"] == "user", f"role changed to {me['role']!r} via PATCH /users/me"


@finding(id="F4", severity="Critical", owasp="Injection (OWASP Top 10 A03:2021; API8:2023 Security Misconfiguration)")
def test_sqli_union_in_product_search(api):
    """What: GET /products?search= with a UNION SELECT payload that targets the users table.
    Why: the search string is pasted into SQL, so an anonymous caller can read any table (here: usernames and password hashes).
    Severity: Critical
    Repro: curl -s -G http://127.0.0.1:8000/products --data-urlencode "search=zzz' UNION SELECT id, username || ':' || password_hash, 0, 0 FROM users--"
    """
    payload = "zzz' UNION SELECT id, username || ':' || password_hash, 0, 0 FROM users--"
    r = api.get("/products", params={"search": payload})
    assert r.status_code == 200
    names = [p["name"] for p in r.json()]
    assert names == [], f"injection returned rows: {names[:3]}"


@finding(id="F4", severity="Critical", owasp="Injection (OWASP Top 10 A03:2021; API8:2023 Security Misconfiguration)")
def test_sqli_quote_in_search_is_handled(api):
    """What: GET /products?search=O'Reilly (a normal apostrophe).
    Why: a 500 with a raw database error on a quote is the classic sign of string-built SQL, and it leaks internals.
    Severity: Critical (same root cause as the UNION test)
    Repro: curl -s -G http://127.0.0.1:8000/products --data-urlencode "search=O'Reilly"
    """
    r = api.get("/products", params={"search": "O'Reilly"})
    assert r.status_code == 200, f"HTTP {r.status_code}: {r.text[:120]}"


@finding(id="F5", severity="Medium", owasp="API3:2023 Broken Object Property Level Authorization (excessive data exposure)")
def test_profile_does_not_expose_password_hash(api):
    """What: GET /users/me as alice; the response must not contain credential fields.
    Why: password hashes in API responses end up in browser caches, logs and analytics, and can be cracked offline.
    Severity: Medium
    Repro: curl -s -H 'Authorization: Bearer alice-token' http://127.0.0.1:8000/users/me
    """
    body = api.get("/users/me", as_user="alice").json()
    assert "password_hash" not in body, "password_hash present in /users/me"


@finding(id="F5", severity="Medium", owasp="API3:2023 Broken Object Property Level Authorization (excessive data exposure)")
def test_admin_user_list_does_not_expose_password_hash(api):
    """What: GET /admin/users as admin; even admins must not receive password hashes.
    Why: the admin UI never needs them; leaking them widens the blast radius of any admin-session compromise.
    Severity: Medium
    Repro: curl -s -H 'Authorization: Bearer admin-token' http://127.0.0.1:8000/admin/users
    """
    users = api.get("/admin/users", as_user="admin").json()
    leaked = [u["username"] for u in users if "password_hash" in u]
    assert not leaked, f"password_hash returned for: {leaked}"


def _spec_total(lines, pct):
    """Reference implementation of docs/pricing-spec.md (Decimal, half-up, discount once)."""
    subtotal = sum(Decimal(p) * q for p, q in lines)
    discount = (subtotal * pct / 100).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    return f"{subtotal - discount:.2f}"


@finding(id="F6", severity="High", owasp="Data accuracy (business logic) - pricing spec section 'Money'")
@pytest.mark.parametrize("items,lines", [
    ([{"product_id": 1, "quantity": 3}], [("9.99", 3)]),
    ([{"product_id": 3, "quantity": 2}, {"product_id": 1, "quantity": 1}], [("19.99", 2), ("9.99", 1)]),
    ([{"product_id": 2, "quantity": 1}], [("49.95", 1)]),
], ids=["3x-cable", "mixed-cart", "keyboard-half-cent"])
def test_order_total_with_coupon_matches_spec(api, items, lines):
    """What: POST /orders with coupon SAVE10; compare total with the spec (10% off subtotal once, half-up).
    Why: wrong totals mean customers are over/under-charged on every discounted order, a direct revenue and compliance problem.
    Severity: High
    Repro: curl -s -X POST -H 'Authorization: Bearer alice-token' -H 'Content-Type: application/json' -d '{"items":[{"product_id":1,"quantity":3}],"coupon":"SAVE10"}' http://127.0.0.1:8000/orders
    """
    r = api.post("/orders", as_user="alice", json={"items": items, "coupon": "SAVE10"})
    assert r.status_code == 201
    expected = _spec_total(lines, 10)
    assert r.json()["total"] == expected, f"total {r.json()['total']} != spec {expected}"


@finding(id="F7", severity="Medium", owasp="API4:2023 Unrestricted Resource Consumption (no login throttling)")
def test_login_locks_after_repeated_failures(api):
    """What: 10 wrong passwords for alice on POST /login; from the 6th attempt the API must answer 429.
    Why: without throttling an attacker can guess passwords at full speed (credential stuffing / brute force).
    Severity: Medium
    Repro: for i in $(seq 1 10); do curl -s -o /dev/null -w '%{http_code} ' -X POST -H 'Content-Type: application/json' -d '{"username":"alice","password":"wrong'$i'"}' http://127.0.0.1:8000/login; done
    """
    codes = [api.post("/login", json={"username": "alice", "password": f"wrong{i}"}).status_code for i in range(1, 11)]
    assert codes[:5] == [401] * 5
    assert all(c == 429 for c in codes[5:]), f"status codes for 10 bad logins: {codes}"
