# API Security & Data-Accuracy Test Report (SAMPLE)

> Sample engagement against **Demo Shop API**, a demo app with deliberately seeded flaws (`demo_api/app.py`). It is not a real target. Every number, status code and response below was produced by the test run on 2026-11-13.

## 1. Summary

- Tests executed: **49** (22 permission-matrix cells, 12 security/accuracy checks, 15 functional/format checks).
- Vulnerable build: **17 failed / 32 passed** in 0.76 s, giving **7 distinct findings**: 3 Critical, 2 High, 2 Medium, 0 Low.
- Fixed build: **0 failed / 49 passed** in 0.8 s. Open findings after fix: **0**.
- Most urgent: unauthenticated SQL injection (F4), self-service privilege escalation (F3) and admin routes open to every user (F2). Together they allow full takeover without any special access.

## 2. Scope and method

- Target: Demo Shop API v1.0, run in-process (FastAPI TestClient) and at `http://127.0.0.1:8000` for the curl repro commands.
- Inputs: the API's own documentation (`docs/pricing-spec.md`): access rules, money rules, paging and lockout rules.
- Roles tested: anonymous, user `alice`, second user `bob`, `admin`.
- Method: (1) a role x endpoint x method permission matrix written as data and run as tests; (2) one targeted test per risk, mapped to OWASP API Security Top 10 (2023); (3) data-accuracy tests against a reference implementation of the pricing spec; (4) schema, type and boundary checks. Each test records the real HTTP exchange, which is quoted below as evidence.
- Out of scope: denial-of-service load testing, infrastructure/TLS, third-party services.

## 3. Findings by severity

| Severity | Findings | IDs |
|---|---|---|
| Critical | 3 | F2, F3, F4 |
| High | 2 | F1, F6 |
| Medium | 2 | F5, F7 |
| Low | 0 | - |
| **Total** | **7** | |

## 4. Findings

### F2 - Normal users can call admin functions (BFLA)

- **Severity:** Critical
- **Category:** API5:2023 Broken Function Level Authorization
- **Endpoint:** `GET /admin/users, POST /admin/products`
- **Scenario:** Logged in as alice (role=user), call the admin user list and the admin product-create endpoint.
- **Failing tests:** 2/2 (`test_bfla_normal_user_cannot_list_all_users`, `test_bfla_normal_user_cannot_create_products`)

**Repro (curl)**

```bash
curl -s -H 'Authorization: Bearer alice-token' http://127.0.0.1:8000/admin/users
```

**Evidence (from the test run, vulnerable build)**

`test_bfla_normal_user_cannot_list_all_users`:

```http
> GET /admin/users
> Authorization: Bearer alice-token
< HTTP 200
< [{"id":1,"username":"alice","email":"alice@example.test","display_name":"Alice","role":"user","password_hash":"6198f50cba51030c361ff55c6c2c32928f09ff71144cda86a1e22ff5d664b7fd"},{"id":2,"username":"bob","email":"bob@example.test","display_name":"Bob","role":"user","password_hash":"7df25982c15c54e4067025d5e0de9f3ff26d289b980752883646666a706e133a"},{"id":3,"username":"admin","email":"admin@example.test","display_name": ...[trimmed]
```

> non-admin got HTTP 200 on /admin/users

`test_bfla_normal_user_cannot_create_products`:

```http
> POST /admin/products
> Authorization: Bearer alice-token
> {"name": "x", "price": "0.01", "stock": 1}
< HTTP 201
< {"id":5,"name":"x","price":"0.01","stock":1}
```

> non-admin got HTTP 201 on POST /admin/products

**Impact:** Any customer can list all accounts (including the admin) and change the product catalog and prices.

**Fix:** Enforce the role in one shared dependency used by every /admin route, deny by default.

```python
def require_admin(user = Depends(current_user)):
    if user.role != "admin":
        raise HTTPException(403, "admin role required")
    return user

admin = APIRouter(prefix="/admin", dependencies=[Depends(require_admin)])
```

**Re-test:** PASS after fix (2/2 tests pass)

### F3 - Users can make themselves admin via mass assignment

- **Severity:** Critical
- **Category:** API3:2023 Broken Object Property Level Authorization (mass assignment)
- **Endpoint:** `PATCH /users/me`
- **Scenario:** alice sends {"role": "admin"} to her own profile update endpoint.
- **Failing tests:** 1/1 (`test_mass_assignment_cannot_set_role`)

**Repro (curl)**

```bash
curl -s -X PATCH -H 'Authorization: Bearer alice-token' -H 'Content-Type: application/json' -d '{"role":"admin"}' http://127.0.0.1:8000/users/me
```

**Evidence (from the test run, vulnerable build)**

`test_mass_assignment_cannot_set_role`:

```http
> PATCH /users/me
> Authorization: Bearer alice-token
> {"role": "admin"}
< HTTP 200
< {"id":1,"username":"alice","email":"alice@example.test","display_name":"Alice","role":"admin","password_hash":"6198f50cba51030c361ff55c6c2c32928f09ff71144cda86a1e22ff5d664b7fd"}

> GET /users/me
> Authorization: Bearer alice-token
< HTTP 200
< {"id":1,"username":"alice","email":"alice@example.test","display_name":"Alice","role":"admin","password_hash":"6198f50cba51030c361ff55c6c2c32928f09ff71144cda86a1e22ff5d664b7fd"}
```

> role changed to 'admin' via PATCH /users/me

**Impact:** Full privilege escalation in one request; combined with F2's admin routes this is a complete takeover.

**Fix:** Accept only an explicit allow-list of writable fields (a strict input model) and reject anything else.

```python
class ProfileUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr | None = None
    display_name: str | None = Field(None, max_length=100)
```

**Re-test:** PASS after fix (1/1 tests pass)

### F4 - SQL injection in product search (unauthenticated)

- **Severity:** Critical
- **Category:** Injection (OWASP Top 10 A03:2021; API8:2023 Security Misconfiguration)
- **Endpoint:** `GET /products?search=`
- **Scenario:** Anonymous request with a UNION SELECT payload in `search`; also a plain apostrophe (O'Reilly).
- **Failing tests:** 2/2 (`test_sqli_union_in_product_search`, `test_sqli_quote_in_search_is_handled`)

**Repro (curl)**

```bash
curl -s -G http://127.0.0.1:8000/products --data-urlencode "search=zzz' UNION SELECT id, username || ':' || password_hash, 0, 0 FROM users--"
```

**Evidence (from the test run, vulnerable build)**

`test_sqli_union_in_product_search`:

```http
> GET /products?search=zzz' UNION SELECT id, username || ':' || password_hash, 0, 0 FROM users--
< HTTP 200
< [{"id":1,"name":"alice:6198f50cba51030c361ff55c6c2c32928f09ff71144cda86a1e22ff5d664b7fd","price":"0.00","stock":0},{"id":2,"name":"bob:7df25982c15c54e4067025d5e0de9f3ff26d289b980752883646666a706e133a","price":"0.00","stock":0},{"id":3,"name":"admin:5eedc43e05a907377fb402da8d59d48af0115cb9528cdc1e0987765837e758a9","price":"0.00","stock":0}]
```

> injection returned rows: ['alice:6198f50cba51030c361ff55c6c2c32928f09ff71144cda86a1e22ff5d664b7fd', 'bob:7df25982c15c54e4067025d5e0de9f3ff26d289b980752883646666a706e133a', 'admin:5eedc43e05a907377fb402da8d59d48af0115cb95

`test_sqli_quote_in_search_is_handled`:

```http
> GET /products?search=O'Reilly
< HTTP 500
< {"detail":"database error: near \"Reilly\": syntax error"}
```

> HTTP 500: {"detail":"database error: near \"Reilly\": syntax error"}

**Impact:** Anyone on the internet can read any table, here all usernames and password hashes; quotes also crash search with a raw DB error.

**Fix:** Use bound parameters for every value (never f-strings), and return a generic error message.

```python
rows = db.execute(
    "SELECT id, name, price_cents, stock FROM products WHERE name LIKE ? ORDER BY id LIMIT ?",
    (f"%{search}%", limit),
).fetchall()
```

**Re-test:** PASS after fix (2/2 tests pass)

### F1 - Any user can read any other user's order (BOLA / IDOR)

- **Severity:** High
- **Category:** API1:2023 Broken Object Level Authorization
- **Endpoint:** `GET /orders/{id}`
- **Scenario:** Logged in as bob, request order 1, which belongs to alice.
- **Failing tests:** 1/1 (`test_bola_user_cannot_read_other_users_order`)

**Repro (curl)**

```bash
curl -s -H 'Authorization: Bearer bob-token' http://127.0.0.1:8000/orders/1
```

**Evidence (from the test run, vulnerable build)**

`test_bola_user_cannot_read_other_users_order`:

```http
> GET /orders/1
> Authorization: Bearer bob-token
< HTTP 200
< {"id":1,"user_id":1,"items":[{"product_id":3,"name":"Wireless mouse","quantity":2,"unit_price":"19.99"}],"coupon":null,"subtotal":"39.98","discount":"0.00","total":"39.98","status":"paid"}
```

> bob read alice's order: HTTP 200

**Impact:** Order IDs are sequential, so one customer can enumerate every order in the shop: items, amounts and user ids.

**Fix:** Check ownership on every object lookup (owner or admin), and return 404 rather than 403 so the id's existence is not confirmed.

```python
order = db.get_order(order_id)
if order is None or (order.user_id != user.id and user.role != "admin"):
    raise HTTPException(404, "order not found")
```

**Re-test:** PASS after fix (1/1 tests pass)

### F6 - Coupon discount applied twice; totals do not match the pricing spec

- **Severity:** High
- **Category:** Data accuracy (business logic) - pricing spec section 'Money'
- **Endpoint:** `POST /orders`
- **Scenario:** Create orders with coupon SAVE10 and compare `total` with docs/pricing-spec.md (10% off the subtotal once, rounded half up).
- **Failing tests:** 3/3 (`test_order_total_with_coupon_matches_spec[3x-cable]`, `test_order_total_with_coupon_matches_spec[mixed-cart]`, `test_order_total_with_coupon_matches_spec[keyboard-half-cent]`)

**Repro (curl)**

```bash
curl -s -X POST -H 'Authorization: Bearer alice-token' -H 'Content-Type: application/json' -d '{"items":[{"product_id":1,"quantity":3}],"coupon":"SAVE10"}' http://127.0.0.1:8000/orders
```

**Evidence (from the test run, vulnerable build)**

`test_order_total_with_coupon_matches_spec[3x-cable]`:

```http
> POST /orders
> Authorization: Bearer alice-token
> {"items": [{"product_id": 1, "quantity": 3}], "coupon": "SAVE10"}
< HTTP 201
< {"id":3,"user_id":1,"items":[{"product_id":1,"name":"USB-C cable","quantity":3,"unit_price":"9.99"}],"coupon":"SAVE10","subtotal":"29.97","discount":"5.69","total":"24.28","status":"pending"}
```

> total 24.28 != spec 26.97

| Cart (SAVE10) | Subtotal | Spec total | API total | Difference |
|---|---|---|---|---|
| `[{'product_id': 1, 'quantity': 3}]` | 29.97 | 26.97 | 24.28 | -2.69 |
| `[{'product_id': 3, 'quantity': 2}, {'product_id': 1, 'quantity': 1}]` | 49.97 | 44.97 | 40.48 | -4.49 |
| `[{'product_id': 2, 'quantity': 1}]` | 49.95 | 44.95 | 40.46 | -4.49 |

**Impact:** Every discounted order is under-charged by about 9% of the subtotal (19% off instead of 10%): direct revenue loss and totals that do not reconcile with accounting.

**Fix:** Compute in integer cents (or Decimal), apply the discount once to the subtotal, round half up explicitly.

```python
subtotal = sum(p.price_cents * qty for p, qty in lines)
discount = (subtotal * pct + 50) // 100   # half up
total = subtotal - discount
```

**Re-test:** PASS after fix (3/3 tests pass)

### F5 - Password hashes returned in user objects (excessive data exposure)

- **Severity:** Medium
- **Category:** API3:2023 Broken Object Property Level Authorization (excessive data exposure)
- **Endpoint:** `GET /users/me, GET /admin/users`
- **Scenario:** Read your own profile, and the admin user list as admin.
- **Failing tests:** 2/2 (`test_profile_does_not_expose_password_hash`, `test_admin_user_list_does_not_expose_password_hash`)

**Repro (curl)**

```bash
curl -s -H 'Authorization: Bearer alice-token' http://127.0.0.1:8000/users/me
```

**Evidence (from the test run, vulnerable build)**

`test_profile_does_not_expose_password_hash`:

```http
> GET /users/me
> Authorization: Bearer alice-token
< HTTP 200
< {"id":1,"username":"alice","email":"alice@example.test","display_name":"Alice","role":"user","password_hash":"6198f50cba51030c361ff55c6c2c32928f09ff71144cda86a1e22ff5d664b7fd"}
```

> password_hash present in /users/me

`test_admin_user_list_does_not_expose_password_hash`:

```http
> GET /admin/users
> Authorization: Bearer admin-token
< HTTP 200
< [{"id":1,"username":"alice","email":"alice@example.test","display_name":"Alice","role":"user","password_hash":"6198f50cba51030c361ff55c6c2c32928f09ff71144cda86a1e22ff5d664b7fd"},{"id":2,"username":"bob","email":"bob@example.test","display_name":"Bob","role":"user","password_hash":"7df25982c15c54e4067025d5e0de9f3ff26d289b980752883646666a706e133a"},{"id":3,"username":"admin","email":"admin@example.test","display_name": ...[trimmed]
```

> password_hash returned for: ['alice', 'bob', 'admin']

**Impact:** Hashes leak into browsers, proxies and logs and can be cracked offline; with F2 every customer gets every hash.

**Fix:** Serialize through an explicit response model that lists public fields only.

```python
class UserOut(BaseModel):
    id: int
    username: str
    email: str
    display_name: str
    role: str

@app.get("/users/me", response_model=UserOut)
```

**Re-test:** PASS after fix (2/2 tests pass)

### F7 - No login throttling or account lockout

- **Severity:** Medium
- **Category:** API4:2023 Unrestricted Resource Consumption (no login throttling)
- **Endpoint:** `POST /login`
- **Scenario:** Send 10 wrong passwords for alice in a row.
- **Failing tests:** 1/1 (`test_login_locks_after_repeated_failures`)

**Repro (curl)**

```bash
for i in $(seq 1 10); do curl -s -o /dev/null -w '%{http_code} ' -X POST -H 'Content-Type: application/json' -d '{"username":"alice","password":"wrong'$i'"}' http://127.0.0.1:8000/login; done
```

**Evidence (from the test run, vulnerable build)**

`test_login_locks_after_repeated_failures`:

```http
# 10 requests, status codes in order: 401 401 401 401 401 401 401 401 401 401
> POST /login
> {"username": "alice", "password": "wrong1"}
< HTTP 401
< {"detail":"invalid credentials"}

> POST /login
> {"username": "alice", "password": "wrong10"}
< HTTP 401
< {"detail":"invalid credentials"}
```

> status codes for 10 bad logins: [401, 401, 401, 401, 401, 401, 401, 401, 401, 401]

**Impact:** Unlimited online password guessing and credential stuffing.

**Fix:** Count failures per account (and per IP), lock or slow down after 5 failures, answer 429 with Retry-After.

```python
recent = [t for t in failures[username] if now - t < 900]
if len(recent) >= 5:
    raise HTTPException(429, "too many failed attempts", headers={"Retry-After": "900"})
```

**Re-test:** PASS after fix (1/1 tests pass)

## 5. Permission matrix

Vulnerable build: 5 of 22 cells wrong. Fixed build: 0 of 22 cells wrong.

| Role | Method | Path | Expected | Vulnerable: got | Result | Fixed: got | Result |
|---|---|---|---|---|---|---|---|
| anonymous | GET | `/products` | 200 | 200 | PASS | 200 | PASS |
| alice | GET | `/products` | 200 | 200 | PASS | 200 | PASS |
| anonymous | GET | `/users/me` | 401 | 401 | PASS | 401 | PASS |
| alice | GET | `/users/me` | 200 | 200 | PASS | 200 | PASS |
| anonymous | PATCH | `/users/me` | 401 | 401 | PASS | 401 | PASS |
| alice | PATCH | `/users/me` | 200 | 200 | PASS | 200 | PASS |
| anonymous | GET | `/orders` | 401 | 401 | PASS | 401 | PASS |
| alice | GET | `/orders` | 200 | 200 | PASS | 200 | PASS |
| anonymous | POST | `/orders` | 401 | 401 | PASS | 401 | PASS |
| alice | POST | `/orders` | 201 | 201 | PASS | 201 | PASS |
| anonymous | GET | `/orders/1` | 401 | 401 | PASS | 401 | PASS |
| alice | GET | `/orders/1` | 200 | 200 | PASS | 200 | PASS |
| bob | GET | `/orders/1` | 404 | 200 | **FAIL** | 404 | PASS |
| alice | GET | `/orders/2` | 404 | 200 | **FAIL** | 404 | PASS |
| admin | GET | `/orders/1` | 200 | 200 | PASS | 200 | PASS |
| anonymous | GET | `/admin/users` | 401 | 401 | PASS | 401 | PASS |
| alice | GET | `/admin/users` | 403 | 200 | **FAIL** | 403 | PASS |
| bob | GET | `/admin/users` | 403 | 200 | **FAIL** | 403 | PASS |
| admin | GET | `/admin/users` | 200 | 200 | PASS | 200 | PASS |
| anonymous | POST | `/admin/products` | 401 | 401 | PASS | 401 | PASS |
| alice | POST | `/admin/products` | 403 | 201 | **FAIL** | 403 | PASS |
| admin | POST | `/admin/products` | 201 | 201 | PASS | 201 | PASS |

## 6. Functional and data-format checks

| Check | Vulnerable build | Fixed build |
|---|---|---|
| `test_products_schema_and_types` | PASS | PASS |
| `test_order_schema_and_types` | PASS | PASS |
| `test_order_total_without_coupon` | PASS | PASS |
| `test_order_quantity_boundaries_rejected[-1]` | PASS | PASS |
| `test_order_quantity_boundaries_rejected[0]` | PASS | PASS |
| `test_order_quantity_boundaries_rejected[101]` | PASS | PASS |
| `test_order_quantity_boundaries_rejected[2147483648]` | PASS | PASS |
| `test_page_size_boundaries[1-200]` | PASS | PASS |
| `test_page_size_boundaries[100-200]` | PASS | PASS |
| `test_page_size_boundaries[0-422]` | PASS | PASS |
| `test_page_size_boundaries[101-422]` | PASS | PASS |
| `test_page_size_boundaries[1000000-422]` | PASS | PASS |
| `test_unknown_product_and_coupon` | PASS | PASS |
| `test_invalid_ids_and_tokens` | PASS | PASS |
| `test_successful_login_returns_token` | PASS | PASS |

## 7. Re-test after fix (DEMO_FIXED=1)

| ID | Finding | Severity | Before fix | After fix |
|---|---|---|---|---|
| F1 | Any user can read any other user's order (BOLA / IDOR) | High | 1/1 tests fail | 1/1 pass |
| F2 | Normal users can call admin functions (BFLA) | Critical | 2/2 tests fail | 2/2 pass |
| F3 | Users can make themselves admin via mass assignment | Critical | 1/1 tests fail | 1/1 pass |
| F4 | SQL injection in product search (unauthenticated) | Critical | 2/2 tests fail | 2/2 pass |
| F5 | Password hashes returned in user objects (excessive data exposure) | Medium | 2/2 tests fail | 2/2 pass |
| F6 | Coupon discount applied twice; totals do not match the pricing spec | High | 3/3 tests fail | 3/3 pass |
| F7 | No login throttling or account lockout | Medium | 1/1 tests fail | 1/1 pass |
| | **All tests** | | **17 failed / 49** | **0 failed / 49** |

## 8. How to reproduce

```bash
python -m venv .venv && .venv/bin/pip install fastapi uvicorn httpx pytest
.venv/bin/python tools/report.py            # runs both builds, rewrites this report
DEMO_FIXED=0 .venv/bin/uvicorn demo_api.app:app --host 127.0.0.1 --port 8000   # then use the curl lines above
```

---

*Built by Nightshift Labs, an AI engineering agent operated by Ivan Mollov.*
