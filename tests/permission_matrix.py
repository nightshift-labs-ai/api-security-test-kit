"""Permission matrix: role x endpoint x method -> expected HTTP status.

Written from docs/pricing-spec.md ("Access rules"). One row = one parametrized test.
Order 1 belongs to alice, order 2 belongs to bob.
"""
NEW_ORDER = {"items": [{"product_id": 1, "quantity": 1}]}
NEW_PRODUCT = {"name": "Test product", "price": "1.00", "stock": 1}
PROFILE = {"display_name": "New Name"}

# (role, method, path, json_body, expected_status)
MATRIX = [
    ("anonymous", "GET",   "/products",       None,        200),
    ("alice",     "GET",   "/products",       None,        200),
    ("anonymous", "GET",   "/users/me",       None,        401),
    ("alice",     "GET",   "/users/me",       None,        200),
    ("anonymous", "PATCH", "/users/me",       PROFILE,     401),
    ("alice",     "PATCH", "/users/me",       PROFILE,     200),
    ("anonymous", "GET",   "/orders",         None,        401),
    ("alice",     "GET",   "/orders",         None,        200),
    ("anonymous", "POST",  "/orders",         NEW_ORDER,   401),
    ("alice",     "POST",  "/orders",         NEW_ORDER,   201),
    ("anonymous", "GET",   "/orders/1",       None,        401),
    ("alice",     "GET",   "/orders/1",       None,        200),
    ("bob",       "GET",   "/orders/1",       None,        404),
    ("alice",     "GET",   "/orders/2",       None,        404),
    ("admin",     "GET",   "/orders/1",       None,        200),
    ("anonymous", "GET",   "/admin/users",    None,        401),
    ("alice",     "GET",   "/admin/users",    None,        403),
    ("bob",       "GET",   "/admin/users",    None,        403),
    ("admin",     "GET",   "/admin/users",    None,        200),
    ("anonymous", "POST",  "/admin/products", NEW_PRODUCT, 401),
    ("alice",     "POST",  "/admin/products", NEW_PRODUCT, 403),
    ("admin",     "POST",  "/admin/products", NEW_PRODUCT, 201),
]
