import pytest

from permission_matrix import MATRIX


@pytest.mark.matrix
@pytest.mark.parametrize(
    "role,method,path,body,expected", MATRIX,
    ids=[f"{r}-{m}-{p}" for r, m, p, _, _ in MATRIX],
)
def test_permission_matrix(api, role, method, path, body, expected):
    """What: one cell of the role x endpoint permission matrix (tests/permission_matrix.py).
    Why: broken access control is the #1 API risk (OWASP API1/API5 2023); every role/endpoint pair is checked, not just the obvious ones.
    Severity: depends on the row (an unexpected 2xx on an admin or foreign-object route is High/Critical).
    Repro: curl -s -o /dev/null -w '%{http_code}' -X <METHOD> -H 'Authorization: Bearer <role>-token' http://127.0.0.1:8000<path>
    """
    kw = {"json": body} if body is not None else {}
    r = api.request(method, path, as_user=role, **kw)
    assert r.status_code == expected, f"{role} {method} {path}: expected {expected}, got {r.status_code}"
