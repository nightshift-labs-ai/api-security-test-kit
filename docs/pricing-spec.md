# Demo Shop API - pricing and access spec (the "client docs" the tests are written from)

## Money
- All prices and totals are decimal strings with exactly two decimals, e.g. `"26.97"`.
- `subtotal` = sum of `unit_price x quantity` over all lines.
- Coupon `SAVE10` gives **10 % off the order subtotal, applied once**.
- `discount` = 10 % of `subtotal`, rounded **half up** to the cent.
- `total` = `subtotal - discount`.
- Worked example: 3 x USB-C cable (9.99) with `SAVE10` -> subtotal 29.97, discount 3.00 (2.997 rounded half up), total **26.97**.
- `quantity` must be an integer from 1 to 100. Unknown coupons -> 400. Unknown products -> 404.

## Access rules
- `GET /products`, `GET /health`, `POST /login`: public.
- `GET /users/me`, `PATCH /users/me`, `GET /orders`, `POST /orders`: any logged-in user.
- `GET /orders/{id}`: the owner of the order, or an admin. Anyone else gets 404.
- `/admin/*`: admin role only (others get 403).
- `PATCH /users/me` may change only `email` and `display_name`.
- User objects returned by the API never contain credentials (`password_hash`, tokens).
- Paging: `limit` is 1..100 (default 20).

## Authentication
- `POST /login` returns a bearer token. After 5 failed attempts for one username within 15 minutes
  the account is locked (HTTP 429) for 15 minutes.
