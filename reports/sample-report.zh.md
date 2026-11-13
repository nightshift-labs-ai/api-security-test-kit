# API 安全与数据准确性测试报告（样例）

> 本样例的测试对象是 **Demo Shop API**——一个特意植入了缺陷的演示程序（`demo_api/app.py`），并非真实系统。下文所有数字、状态码和响应内容，均来自 2026-11-13 的实际测试运行结果。

## 1. 概要

- 共执行测试 **49** 项（权限矩阵 22 项、安全/准确性专项 12 项、功能/格式检查 15 项）。
- 有缺陷版本：**失败 17 项 / 通过 32 项**，耗时 0.53 秒，归并为 **7 个独立问题**：严重 3 个、高危 2 个、中危 2 个、低危 0 个。
- 修复后版本：**失败 0 项 / 通过 49 项**，耗时 0.60 秒，遗留问题 **0** 个。
- 最需优先处理：无需登录的 SQL 注入（F4）、用户可自行提权（F3）、管理员接口对所有用户开放（F2）。三者叠加，攻击者无需任何特殊权限即可完全接管系统。

## 2. 测试范围与方法

- 测试对象：Demo Shop API v1.0，测试时进程内运行（FastAPI TestClient）；curl 复现命令针对 `http://127.0.0.1:8000`。
- 依据：接口自身的文档（`docs/pricing-spec.md`），包括访问控制规则、金额计算规则、分页与登录锁定规则。
- 测试角色：匿名用户、普通用户 `alice`、另一普通用户 `bob`、管理员 `admin`。
- 方法：（1）以数据形式编写“角色 × 接口 × 方法”权限矩阵，并逐格生成测试；（2）针对每类风险编写专项测试，对应 OWASP API Security Top 10（2023）；（3）按定价规范编写参考实现，校验金额计算；（4）响应结构、字段类型和边界值检查。每个测试都会记录真实的 HTTP 请求与响应，下文证据即直接引用这些记录。
- 不在本次范围内：压力/拒绝服务测试、基础设施与 TLS 配置、第三方服务。

## 3. 问题严重程度分布

| 严重程度 | 数量 | 编号 |
|---|---|---|
| 严重（Critical） | 3 | F2, F3, F4 |
| 高危（High） | 2 | F1, F6 |
| 中危（Medium） | 2 | F5, F7 |
| 低危（Low） | 0 | - |
| **合计** | **7** | |

## 4. 问题详情

### F2 - 普通用户可调用管理员接口（BFLA 功能级越权）

- **严重程度：** 严重（Critical）
- **类别：** API5:2023 Broken Function Level Authorization
- **接口：** `GET /admin/users, POST /admin/products`
- **测试场景：** 以普通用户 alice 登录，调用管理员的用户列表接口和新建商品接口。
- **失败的测试：** 2/2（`test_bfla_normal_user_cannot_list_all_users`, `test_bfla_normal_user_cannot_create_products`）

**复现命令（curl）**

```bash
curl -s -H 'Authorization: Bearer alice-token' http://127.0.0.1:8000/admin/users
```

**证据（有缺陷版本的实际请求/响应）**

`test_bfla_normal_user_cannot_list_all_users`：

```http
> GET /admin/users
> Authorization: Bearer alice-token
< HTTP 200
< [{"id":1,"username":"alice","email":"alice@example.test","display_name":"Alice","role":"user","password_hash":"6198f50cba51030c361ff55c6c2c32928f09ff71144cda86a1e22ff5d664b7fd"},{"id":2,"username":"bob","email":"bob@example.test","display_name":"Bob","role":"user","password_hash":"7df25982c15c54e4067025d5e0de9f3ff26d289b980752883646666a706e133a"},{"id":3,"username":"admin","email":"admin@example.test","display_name": ...[trimmed]
```

> non-admin got HTTP 200 on /admin/users

`test_bfla_normal_user_cannot_create_products`：

```http
> POST /admin/products
> Authorization: Bearer alice-token
> {"name": "x", "price": "0.01", "stock": 1}
< HTTP 201
< {"id":5,"name":"x","price":"0.01","stock":1}
```

> non-admin got HTTP 201 on POST /admin/products

**影响：** 任何顾客都能拉取全部账号（包括管理员及其密码哈希），还能向商品目录随意新增商品并自定价格。

**修复建议：** 在所有 /admin 路由共用的依赖中统一校验角色，默认拒绝。

```python
def require_admin(user = Depends(current_user)):
    if user.role != "admin":
        raise HTTPException(403, "admin role required")
    return user

admin = APIRouter(prefix="/admin", dependencies=[Depends(require_admin)])
```

**复测结果：** 修复后通过（2/2 项通过）

### F3 - 通过批量赋值，用户可把自己提升为管理员

- **严重程度：** 严重（Critical）
- **类别：** API3:2023 Broken Object Property Level Authorization (mass assignment)
- **接口：** `PATCH /users/me`
- **测试场景：** alice 在修改个人资料的请求里加上 {"role": "admin"}。
- **失败的测试：** 1/1（`test_mass_assignment_cannot_set_role`）

**复现命令（curl）**

```bash
curl -s -X PATCH -H 'Authorization: Bearer alice-token' -H 'Content-Type: application/json' -d '{"role":"admin"}' http://127.0.0.1:8000/users/me
```

**证据（有缺陷版本的实际请求/响应）**

`test_mass_assignment_cannot_set_role`：

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

**影响：** 一个请求即可完成权限提升；配合 F2 的管理员接口，等于整个系统被接管。

**修复建议：** 只接受明确列出的可写字段（使用严格的输入模型），其余字段一律拒绝。

```python
class ProfileUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr | None = None
    display_name: str | None = Field(None, max_length=100)
```

**复测结果：** 修复后通过（1/1 项通过）

### F4 - 商品搜索存在 SQL 注入（无需登录）

- **严重程度：** 严重（Critical）
- **类别：** Injection - OWASP Top 10 A05:2025 (A03:2021), CWE-89; no dedicated API Top 10 2023 category (was API8:2019)
- **接口：** `GET /products?search=`
- **测试场景：** 匿名请求，在 search 参数中放入 UNION SELECT 载荷；另测普通单引号（O'Reilly）。
- **失败的测试：** 2/2（`test_sqli_union_in_product_search`, `test_sqli_quote_in_search_is_handled`）

**复现命令（curl）**

```bash
curl -s -G http://127.0.0.1:8000/products --data-urlencode "search=zzz' UNION SELECT id, username || ':' || password_hash, 0, 0 FROM users--"
```

**证据（有缺陷版本的实际请求/响应）**

`test_sqli_union_in_product_search`：

```http
> GET /products?search=zzz' UNION SELECT id, username || ':' || password_hash, 0, 0 FROM users--
< HTTP 200
< [{"id":1,"name":"alice:6198f50cba51030c361ff55c6c2c32928f09ff71144cda86a1e22ff5d664b7fd","price":"0.00","stock":0},{"id":2,"name":"bob:7df25982c15c54e4067025d5e0de9f3ff26d289b980752883646666a706e133a","price":"0.00","stock":0},{"id":3,"name":"admin:5eedc43e05a907377fb402da8d59d48af0115cb9528cdc1e0987765837e758a9","price":"0.00","stock":0}]
```

> injection returned rows: ['alice:6198f50cba51030c361ff55c6c2c32928f09ff71144cda86a1e22ff5d664b7fd', 'bob:7df25982c15c54e4067025d5e0de9f3ff26d289b980752883646666a706e133a', 'admin:5eedc43e05a907377fb402da8d59d48af0115cb95…

`test_sqli_quote_in_search_is_handled`：

```http
> GET /products?search=O'Reilly
< HTTP 500
< {"detail":"database error: near \"Reilly\": syntax error"}
```

> HTTP 500: {"detail":"database error: near \"Reilly\": syntax error"}

**影响：** 任何人无需登录即可读取任意数据表，本例直接拿到全部用户名和密码哈希；输入单引号还会让搜索报 500 并暴露数据库错误。

**修复建议：** 所有参数都用占位符绑定（不要用字符串拼接 SQL），出错时只返回通用错误信息。

```python
rows = db.execute(
    "SELECT id, name, price_cents, stock FROM products WHERE name LIKE ? ORDER BY id LIMIT ?",
    (f"%{search}%", limit),
).fetchall()
```

**复测结果：** 修复后通过（2/2 项通过）

### F1 - 任意用户可读取他人订单（BOLA / IDOR 越权）

- **严重程度：** 高危（High）
- **类别：** API1:2023 Broken Object Level Authorization
- **接口：** `GET /orders/{id}`
- **测试场景：** 以 bob 身份登录，请求属于 alice 的 1 号订单。
- **失败的测试：** 1/1（`test_bola_user_cannot_read_other_users_order`）

**复现命令（curl）**

```bash
curl -s -H 'Authorization: Bearer bob-token' http://127.0.0.1:8000/orders/1
```

**证据（有缺陷版本的实际请求/响应）**

`test_bola_user_cannot_read_other_users_order`：

```http
> GET /orders/1
> Authorization: Bearer bob-token
< HTTP 200
< {"id":1,"user_id":1,"items":[{"product_id":3,"name":"Wireless mouse","quantity":2,"unit_price":"19.99"}],"coupon":null,"subtotal":"39.98","discount":"0.00","total":"39.98","status":"paid"}
```

> bob read alice's order: HTTP 200

**影响：** 订单 ID 是连续自增的，任何一个普通用户都能逐个遍历全站订单，拿到商品、金额和用户 ID 等信息。

**修复建议：** 每次按 ID 取对象时都校验归属（本人或管理员），并对无权访问的请求返回 404 而不是 403，避免泄露该 ID 是否存在。

```python
order = db.get_order(order_id)
if order is None or (order.user_id != user.id and user.role != "admin"):
    raise HTTPException(404, "order not found")
```

**复测结果：** 修复后通过（1/1 项通过）

### F6 - 优惠券折扣被重复计算，订单金额与定价规范不符

- **严重程度：** 高危（High）
- **类别：** 数据准确性（业务逻辑）——定价规范 Money 一节
- **接口：** `POST /orders`
- **测试场景：** 使用 SAVE10 优惠券下单，将返回的 total 与 docs/pricing-spec.md 对比（按小计打一次 9 折，四舍五入到分）。
- **失败的测试：** 3/3（`test_order_total_with_coupon_matches_spec[3x-cable]`, `test_order_total_with_coupon_matches_spec[mixed-cart]`, `test_order_total_with_coupon_matches_spec[keyboard-x3-half-up]`）

**复现命令（curl）**

```bash
curl -s -X POST -H 'Authorization: Bearer alice-token' -H 'Content-Type: application/json' -d '{"items":[{"product_id":1,"quantity":3}],"coupon":"SAVE10"}' http://127.0.0.1:8000/orders
```

**证据（有缺陷版本的实际请求/响应）**

`test_order_total_with_coupon_matches_spec[3x-cable]`：

```http
> POST /orders
> Authorization: Bearer alice-token
> {"items": [{"product_id": 1, "quantity": 3}], "coupon": "SAVE10"}
< HTTP 201
< {"id":3,"user_id":1,"items":[{"product_id":1,"name":"USB-C cable","quantity":3,"unit_price":"9.99"}],"coupon":"SAVE10","subtotal":"29.97","discount":"5.69","total":"24.28","status":"pending"}
```

> total 24.28 != spec 26.97

| 购物车（SAVE10） | 小计 | 规范应收 | 接口返回 | 差额 |
|---|---|---|---|---|
| 3 × USB-C cable | 29.97 | 26.97 | 24.28 | -2.69 |
| 2 × Wireless mouse + 1 × USB-C cable | 49.97 | 44.97 | 40.48 | -4.49 |
| 3 × Mechanical keyboard | 149.85 | 134.86 | 121.38 | -13.48 |

**影响：** 每笔使用优惠券的订单都少收约小计的 9%（实际打了 81 折而非 9 折），直接造成收入损失，且账目无法对平。

**修复建议：** 用整数“分”（或 Decimal）计算，只对小计打一次折扣，并显式使用四舍五入。

```python
subtotal = sum(p.price_cents * qty for p, qty in lines)
discount = (subtotal * pct + 50) // 100   # half up
total = subtotal - discount
```

**复测结果：** 修复后通过（3/3 项通过）

### F5 - 用户对象中返回了密码哈希（数据过度暴露）

- **严重程度：** 中危（Medium）
- **类别：** API3:2023 Broken Object Property Level Authorization (excessive data exposure)
- **接口：** `GET /users/me, GET /admin/users`
- **测试场景：** 读取自己的资料；以管理员身份读取用户列表。
- **失败的测试：** 2/2（`test_profile_does_not_expose_password_hash`, `test_admin_user_list_does_not_expose_password_hash`）

**复现命令（curl）**

```bash
curl -s -H 'Authorization: Bearer alice-token' http://127.0.0.1:8000/users/me
```

**证据（有缺陷版本的实际请求/响应）**

`test_profile_does_not_expose_password_hash`：

```http
> GET /users/me
> Authorization: Bearer alice-token
< HTTP 200
< {"id":1,"username":"alice","email":"alice@example.test","display_name":"Alice","role":"user","password_hash":"6198f50cba51030c361ff55c6c2c32928f09ff71144cda86a1e22ff5d664b7fd"}
```

> password_hash present in /users/me

`test_admin_user_list_does_not_expose_password_hash`：

```http
> GET /admin/users
> Authorization: Bearer admin-token
< HTTP 200
< [{"id":1,"username":"alice","email":"alice@example.test","display_name":"Alice","role":"user","password_hash":"6198f50cba51030c361ff55c6c2c32928f09ff71144cda86a1e22ff5d664b7fd"},{"id":2,"username":"bob","email":"bob@example.test","display_name":"Bob","role":"user","password_hash":"7df25982c15c54e4067025d5e0de9f3ff26d289b980752883646666a706e133a"},{"id":3,"username":"admin","email":"admin@example.test","display_name": ...[trimmed]
```

> password_hash returned for: ['alice', 'bob', 'admin']

**影响：** 哈希会落入浏览器、代理和日志，可被离线破解；叠加 F2 后，任何顾客都能拿到所有人的哈希。

**修复建议：** 通过显式的响应模型序列化，只输出公开字段。

```python
class UserOut(BaseModel):
    id: int
    username: str
    email: str
    display_name: str
    role: str

@app.get("/users/me", response_model=UserOut)
```

**复测结果：** 修复后通过（2/2 项通过）

### F7 - 登录接口无频率限制、无账号锁定

- **严重程度：** 中危（Medium）
- **类别：** API2:2023 Broken Authentication (no brute-force protection / account lockout)
- **接口：** `POST /login`
- **测试场景：** 连续 10 次用错误密码登录 alice。
- **失败的测试：** 1/1（`test_login_locks_after_repeated_failures`）

**复现命令（curl）**

```bash
for i in $(seq 1 10); do curl -s -o /dev/null -w '%{http_code} ' -X POST -H 'Content-Type: application/json' -d '{"username":"alice","password":"wrong'$i'"}' http://127.0.0.1:8000/login; done
```

**证据（有缺陷版本的实际请求/响应）**

`test_login_locks_after_repeated_failures`：

```http
# 共 10 个请求，状态码依次为：401 401 401 401 401 401 401 401 401 401
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

**影响：** 攻击者可无限次在线猜密码或撞库。

**修复建议：** 按账号（及 IP）统计失败次数，连续失败 5 次后锁定或限速，返回 429 并带 Retry-After。

```python
recent = [t for t in failures[username] if now - t < 900]
if len(recent) >= 5:
    raise HTTPException(429, "too many failed attempts", headers={"Retry-After": "900"})
```

**复测结果：** 修复后通过（1/1 项通过）

## 5. 权限矩阵

有缺陷版本：22 格中有 5 格不符合预期；修复后版本：0 格不符合预期。

| 角色 | 方法 | 路径 | 预期 | 有缺陷版本实际 | 结果 | 修复后实际 | 结果 |
|---|---|---|---|---|---|---|---|
| anonymous | GET | `/products` | 200 | 200 | 通过 | 200 | 通过 |
| alice | GET | `/products` | 200 | 200 | 通过 | 200 | 通过 |
| anonymous | GET | `/users/me` | 401 | 401 | 通过 | 401 | 通过 |
| alice | GET | `/users/me` | 200 | 200 | 通过 | 200 | 通过 |
| anonymous | PATCH | `/users/me` | 401 | 401 | 通过 | 401 | 通过 |
| alice | PATCH | `/users/me` | 200 | 200 | 通过 | 200 | 通过 |
| anonymous | GET | `/orders` | 401 | 401 | 通过 | 401 | 通过 |
| alice | GET | `/orders` | 200 | 200 | 通过 | 200 | 通过 |
| anonymous | POST | `/orders` | 401 | 401 | 通过 | 401 | 通过 |
| alice | POST | `/orders` | 201 | 201 | 通过 | 201 | 通过 |
| anonymous | GET | `/orders/1` | 401 | 401 | 通过 | 401 | 通过 |
| alice | GET | `/orders/1` | 200 | 200 | 通过 | 200 | 通过 |
| bob | GET | `/orders/1` | 404 | 200 | **失败** | 404 | 通过 |
| alice | GET | `/orders/2` | 404 | 200 | **失败** | 404 | 通过 |
| admin | GET | `/orders/1` | 200 | 200 | 通过 | 200 | 通过 |
| anonymous | GET | `/admin/users` | 401 | 401 | 通过 | 401 | 通过 |
| alice | GET | `/admin/users` | 403 | 200 | **失败** | 403 | 通过 |
| bob | GET | `/admin/users` | 403 | 200 | **失败** | 403 | 通过 |
| admin | GET | `/admin/users` | 200 | 200 | 通过 | 200 | 通过 |
| anonymous | POST | `/admin/products` | 401 | 401 | 通过 | 401 | 通过 |
| alice | POST | `/admin/products` | 403 | 201 | **失败** | 403 | 通过 |
| admin | POST | `/admin/products` | 201 | 201 | 通过 | 201 | 通过 |

## 6. 功能与数据格式检查

| 检查项 | 有缺陷版本 | 修复后版本 |
|---|---|---|
| `test_products_schema_and_types` | 通过 | 通过 |
| `test_order_schema_and_types` | 通过 | 通过 |
| `test_order_total_without_coupon` | 通过 | 通过 |
| `test_order_quantity_boundaries_rejected[-1]` | 通过 | 通过 |
| `test_order_quantity_boundaries_rejected[0]` | 通过 | 通过 |
| `test_order_quantity_boundaries_rejected[101]` | 通过 | 通过 |
| `test_order_quantity_boundaries_rejected[2147483648]` | 通过 | 通过 |
| `test_page_size_boundaries[1-200]` | 通过 | 通过 |
| `test_page_size_boundaries[100-200]` | 通过 | 通过 |
| `test_page_size_boundaries[0-422]` | 通过 | 通过 |
| `test_page_size_boundaries[101-422]` | 通过 | 通过 |
| `test_page_size_boundaries[1000000-422]` | 通过 | 通过 |
| `test_unknown_product_and_coupon` | 通过 | 通过 |
| `test_invalid_ids_and_tokens` | 通过 | 通过 |
| `test_successful_login_returns_token` | 通过 | 通过 |

## 7. 修复后复测（DEMO_FIXED=1）

| 编号 | 问题 | 严重程度 | 修复前 | 修复后 |
|---|---|---|---|---|
| F1 | 任意用户可读取他人订单（BOLA / IDOR 越权） | 高危（High） | 1/1 项失败 | 1/1 项通过 |
| F2 | 普通用户可调用管理员接口（BFLA 功能级越权） | 严重（Critical） | 2/2 项失败 | 2/2 项通过 |
| F3 | 通过批量赋值，用户可把自己提升为管理员 | 严重（Critical） | 1/1 项失败 | 1/1 项通过 |
| F4 | 商品搜索存在 SQL 注入（无需登录） | 严重（Critical） | 2/2 项失败 | 2/2 项通过 |
| F5 | 用户对象中返回了密码哈希（数据过度暴露） | 中危（Medium） | 2/2 项失败 | 2/2 项通过 |
| F6 | 优惠券折扣被重复计算，订单金额与定价规范不符 | 高危（High） | 3/3 项失败 | 3/3 项通过 |
| F7 | 登录接口无频率限制、无账号锁定 | 中危（Medium） | 1/1 项失败 | 1/1 项通过 |
| | **全部测试** | | **失败 17 / 共 49** | **失败 0 / 共 49** |

## 8. 复现方法

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python tools/report.py            # 运行两个版本并重新生成本报告
DEMO_FIXED=0 .venv/bin/uvicorn demo_api.app:app --host 127.0.0.1 --port 8000   # 启动后即可执行上文的 curl 命令
```

---

*本报告由 Nightshift Labs 完成。Nightshift Labs 是由 Ivan Mollov 运营的 AI 工程代理。*
