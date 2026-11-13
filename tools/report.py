"""Run the suite against the vulnerable and the fixed build, then write EN + ZH reports.

Usage:  python tools/report.py
Writes: runs/vulnerable.txt, runs/fixed.txt (raw pytest output), runs/*.json (structured results),
        reports/sample-report.en.md, reports/sample-report.zh.md
"""
from __future__ import annotations

import datetime as dt
import json
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import unquote_plus

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests"))
from findings_catalog import CATALOG  # noqa: E402
from permission_matrix import MATRIX  # noqa: E402

SEVERITIES = ["Critical", "High", "Medium", "Low"]
SEV_ZH = {"Critical": "严重", "High": "高危", "Medium": "中危", "Low": "低危"}
BASE = "http://127.0.0.1:8000"


def run(mode: str) -> dict:
    env = dict(os.environ, DEMO_FIXED="1" if mode == "fixed" else "0",
               APISEC_RESULTS_JSON=str(ROOT / "runs" / f"{mode}.json"))
    cmd = [sys.executable, "-m", "pytest", "-v", "-rf", "--tb=line"]
    p = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True, timeout=280)
    header = f"# mode={mode} DEMO_FIXED={env['DEMO_FIXED']} cmd: pytest -v -rf --tb=line  ({dt.datetime.now():%Y-%m-%d %H:%M:%S})\n"
    out = (p.stdout + p.stderr).replace(str(ROOT) + "/", "").replace(str(ROOT), ".").replace(sys.prefix, "<venv>")
    (ROOT / "runs" / f"{mode}.txt").write_text(header + out)
    data = json.loads((ROOT / "runs" / f"{mode}.json").read_text())
    data["exit_code"] = p.returncode
    return data


def stats(data: dict) -> dict:
    tests = data["tests"]
    failed = [t for t in tests if t["outcome"] == "failed"]
    findings: dict[str, dict] = {}
    for t in tests:
        if t["finding"]:
            f = findings.setdefault(t["finding"]["id"], {**t["finding"], "tests": [], "failed": []})
            f["tests"].append(t)
            if t["outcome"] == "failed":
                f["failed"].append(t)
    open_ = {k: v for k, v in findings.items() if v["failed"]}
    return {"total": len(tests), "failed": len(failed), "passed": len(tests) - len(failed),
            "findings": findings, "open": open_, "sev": Counter(v["severity"] for v in open_.values()),
            "duration": f"{data['duration_s']:.2f}",
            "by_kind": Counter((t["kind"], t["outcome"]) for t in tests)}


def evidence(test: dict, max_ex: int = 3) -> str:
    ex = test["exchanges"]
    if len(ex) > max_ex:  # e.g. the 10-request brute-force test: show first and last, summarise the rest
        codes = " ".join(str(e["status"]) for e in ex)
        ex = [ex[0], ex[-1]]
        note = f"# {len(test['exchanges'])} requests, status codes in order: {codes}\n"
    else:
        note = ""
    out = []
    for e in ex:
        lines = [f"> {e['method']} {unquote_plus(e['url'])}"]
        if e["auth"]:
            lines.append(f"> Authorization: {e['auth']}")
        if e["json"] is not None:
            lines.append(f"> {json.dumps(e['json'], ensure_ascii=False)}")
        body = e["body"] if len(e["body"]) <= 420 else e["body"][:420] + " ...[trimmed]"
        lines += [f"< HTTP {e['status']}", f"< {body}"]
        out.append("\n".join(lines))
    return note + "\n\n".join(out)


def matrix_rows(v: dict, f: dict) -> list[tuple]:
    def idx(data):
        r = {}
        for t in data["tests"]:
            if t["kind"] == "matrix":
                p = t["params"]
                r[(p["role"], p["method"], p["path"])] = t
        return r
    vi, fi = idx(v), idx(f)
    rows = []
    for role, method, path, _, expected in MATRIX:
        a, b = vi[(role, method, path)], fi[(role, method, path)]
        st = lambda t: t["exchanges"][-1]["status"] if t["exchanges"] else "-"  # noqa: E731
        rows.append((role, method, path, expected, st(a), a["outcome"], st(b), b["outcome"]))
    return rows


T = {
    "en": {
        "title": "API Security & Data-Accuracy Test Report (SAMPLE)",
        "note": "Sample engagement against **Demo Shop API**, a demo app with deliberately seeded flaws (`demo_api/app.py`). It is not a real target. Every number, status code and response below was produced by the test run on {date}.",
        "summary": "Summary", "scope": "Scope and method", "sevtable": "Findings by severity",
        "findings": "Findings", "matrix": "Permission matrix", "functional": "Functional and data-format checks",
        "retest": "Re-test after fix (DEMO_FIXED=1)", "repro": "How to reproduce",
        "sum_lines": [
            "Tests executed: **{total}** ({matrix} permission-matrix cells, {finding} security/accuracy checks, {functional} functional/format checks).",
            "Vulnerable build: **{vfail} failed / {vpass} passed** in {vdur} s, giving **{nfind} distinct findings**: {sevs}.",
            "Fixed build: **{ffail} failed / {fpass} passed** in {fdur} s. Open findings after fix: **{ffind}**.",
            "Most urgent: unauthenticated SQL injection (F4), self-service privilege escalation (F3) and admin routes open to every user (F2). Together they allow full takeover without any special access.",
        ],
        "scope_lines": [
            "Target: Demo Shop API v1.0, run in-process (FastAPI TestClient) and at `" + BASE + "` for the curl repro commands.",
            "Inputs: the API's own documentation (`docs/pricing-spec.md`): access rules, money rules, paging and lockout rules.",
            "Roles tested: anonymous, user `alice`, second user `bob`, `admin`.",
            "Method: (1) a role x endpoint x method permission matrix written as data and run as tests; (2) one targeted test per risk, mapped to OWASP API Security Top 10 (2023); (3) data-accuracy tests against a reference implementation of the pricing spec; (4) schema, type and boundary checks. Each test records the real HTTP exchange, which is quoted below as evidence.",
            "Out of scope: denial-of-service load testing, infrastructure/TLS, third-party services.",
        ],
        "sev_hdr": "| Severity | Findings | IDs |\n|---|---|---|",
        "f_sev": "Severity", "f_owasp": "Category", "f_endpoint": "Endpoint", "f_scen": "Scenario",
        "f_tests": "Failing tests", "f_repro": "Repro (curl)", "f_evid": "Evidence (from the test run, vulnerable build)",
        "f_impact": "Impact", "f_fix": "Fix", "f_retest": "Re-test",
        "retest_ok": "PASS after fix ({n}/{n} tests pass)", "retest_bad": "STILL FAILING ({k}/{n} tests fail)",
        "m_hdr": "| Role | Method | Path | Expected | Vulnerable: got | Result | Fixed: got | Result |\n|---|---|---|---|---|---|---|---|",
        "m_sum": "Vulnerable build: {vf} of {n} cells wrong. Fixed build: {ff} of {n} cells wrong.",
        "fn_hdr": "| Check | Vulnerable build | Fixed build |\n|---|---|---|",
        "r_hdr": "| ID | Finding | Severity | Before fix | After fix |\n|---|---|---|---|---|",
        "r_tot": "| | **All tests** | | **{vf} failed / {n}** | **{ff} failed / {n}** |",
        "before": "{k}/{n} tests fail", "after_ok": "{n}/{n} pass", "after_bad": "{k}/{n} fail",
        "repro_txt": "```bash\npython3 -m venv .venv && .venv/bin/pip install -r requirements.txt\n.venv/bin/python tools/report.py            # runs both builds, rewrites this report\nDEMO_FIXED=0 .venv/bin/uvicorn demo_api.app:app --host 127.0.0.1 --port 8000   # then use the curl lines above\n```",
        "footer": "Built by Nightshift Labs, an AI engineering agent operated by Ivan Mollov.",
        "pass": "PASS", "fail": "FAIL", "none": "-",
        "acc_hdr": "| Cart (SAVE10) | Subtotal | Spec total | API total | Difference |\n|---|---|---|---|---|",
    },
    "zh": {
        "title": "API 安全与数据准确性测试报告（样例）",
        "note": "本样例的测试对象是 **Demo Shop API**——一个特意植入了缺陷的演示程序（`demo_api/app.py`），并非真实系统。下文所有数字、状态码和响应内容，均来自 {date} 的实际测试运行结果。",
        "summary": "概要", "scope": "测试范围与方法", "sevtable": "问题严重程度分布",
        "findings": "问题详情", "matrix": "权限矩阵", "functional": "功能与数据格式检查",
        "retest": "修复后复测（DEMO_FIXED=1）", "repro": "复现方法",
        "sum_lines": [
            "共执行测试 **{total}** 项（权限矩阵 {matrix} 项、安全/准确性专项 {finding} 项、功能/格式检查 {functional} 项）。",
            "有缺陷版本：**失败 {vfail} 项 / 通过 {vpass} 项**，耗时 {vdur} 秒，归并为 **{nfind} 个独立问题**：{sevs}。",
            "修复后版本：**失败 {ffail} 项 / 通过 {fpass} 项**，耗时 {fdur} 秒，遗留问题 **{ffind}** 个。",
            "最需优先处理：无需登录的 SQL 注入（F4）、用户可自行提权（F3）、管理员接口对所有用户开放（F2）。三者叠加，攻击者无需任何特殊权限即可完全接管系统。",
        ],
        "scope_lines": [
            "测试对象：Demo Shop API v1.0，测试时进程内运行（FastAPI TestClient）；curl 复现命令针对 `" + BASE + "`。",
            "依据：接口自身的文档（`docs/pricing-spec.md`），包括访问控制规则、金额计算规则、分页与登录锁定规则。",
            "测试角色：匿名用户、普通用户 `alice`、另一普通用户 `bob`、管理员 `admin`。",
            "方法：(1) 以数据形式编写“角色 × 接口 × 方法”权限矩阵，并逐格生成测试；(2) 针对每类风险编写专项测试，对应 OWASP API Security Top 10（2023）；(3) 按定价规范编写参考实现，校验金额计算；(4) 响应结构、字段类型和边界值检查。每个测试都会记录真实的 HTTP 请求与响应，下文证据即直接引用这些记录。",
            "不在本次范围内：压力/拒绝服务测试、基础设施与 TLS 配置、第三方服务。",
        ],
        "sev_hdr": "| 严重程度 | 数量 | 编号 |\n|---|---|---|",
        "f_sev": "严重程度", "f_owasp": "类别", "f_endpoint": "接口", "f_scen": "测试场景",
        "f_tests": "失败的测试", "f_repro": "复现命令（curl）", "f_evid": "证据（有缺陷版本的实际请求/响应）",
        "f_impact": "影响", "f_fix": "修复建议", "f_retest": "复测结果",
        "retest_ok": "修复后通过（{n}/{n} 项通过）", "retest_bad": "仍未通过（{k}/{n} 项失败）",
        "m_hdr": "| 角色 | 方法 | 路径 | 预期 | 有缺陷版本实际 | 结果 | 修复后实际 | 结果 |\n|---|---|---|---|---|---|---|---|",
        "m_sum": "有缺陷版本：{n} 格中有 {vf} 格不符合预期；修复后版本：{ff} 格不符合预期。",
        "fn_hdr": "| 检查项 | 有缺陷版本 | 修复后版本 |\n|---|---|---|",
        "r_hdr": "| 编号 | 问题 | 严重程度 | 修复前 | 修复后 |\n|---|---|---|---|---|",
        "r_tot": "| | **全部测试** | | **失败 {vf} / 共 {n}** | **失败 {ff} / 共 {n}** |",
        "before": "{k}/{n} 项失败", "after_ok": "{n}/{n} 项通过", "after_bad": "{k}/{n} 项失败",
        "repro_txt": "```bash\npython3 -m venv .venv && .venv/bin/pip install -r requirements.txt\n.venv/bin/python tools/report.py            # 运行两个版本并重新生成本报告\nDEMO_FIXED=0 .venv/bin/uvicorn demo_api.app:app --host 127.0.0.1 --port 8000   # 启动后即可执行上文的 curl 命令\n```",
        "footer": "本报告由 Nightshift Labs 完成。Nightshift Labs 是由 Ivan Mollov 运营的 AI 工程代理。",
        "pass": "通过", "fail": "失败", "none": "-",
        "acc_hdr": "| 购物车（SAVE10） | 小计 | 规范应收 | 接口返回 | 差额 |\n|---|---|---|---|---|",
    },
}


def sev_label(sev: str, lang: str) -> str:
    return sev if lang == "en" else f"{SEV_ZH[sev]}（{sev}）"


def build(lang: str, v: dict, f: dict, vs: dict, fs: dict) -> str:
    t = T[lang]
    date = dt.date.today().isoformat()
    ok = lambda o: t["pass"] if o == "passed" else t["fail"]  # noqa: E731
    order = sorted(vs["open"].values(), key=lambda x: (SEVERITIES.index(x["severity"]), x["id"]))
    sevs = (", ".join(f"{vs['sev'].get(s, 0)} {s}" for s in SEVERITIES) if lang == "en"
            else "、".join(f"{SEV_ZH[s]} {vs['sev'].get(s, 0)} 个" for s in SEVERITIES))
    kinds = Counter(x["kind"] for x in v["tests"])
    L = [f"# {t['title']}", "", f"> {t['note'].format(date=date)}", "", f"## 1. {t['summary']}", ""]
    L += [f"- {s.format(total=vs['total'], matrix=kinds['matrix'], finding=kinds['finding'], functional=kinds['functional'], vfail=vs['failed'], vpass=vs['passed'], vdur=vs['duration'], nfind=len(vs['open']), sevs=sevs, ffail=fs['failed'], fpass=fs['passed'], fdur=fs['duration'], ffind=len(fs['open']))}" for s in t["sum_lines"]]
    L += ["", f"## 2. {t['scope']}", ""] + [f"- {s}" for s in t["scope_lines"]]
    L += ["", f"## 3. {t['sevtable']}", "", t["sev_hdr"]]
    for s in SEVERITIES:
        ids = [x["id"] for x in order if x["severity"] == s]
        L.append(f"| {sev_label(s, lang)} | {len(ids)} | {', '.join(ids) or t['none']} |")
    L.append(f"| **{'Total' if lang == 'en' else '合计'}** | **{len(order)}** | |")
    L += ["", f"## 4. {t['findings']}", ""]
    for fd in order:
        c = CATALOG[fd["id"]]
        fixed_fd = fs["findings"][fd["id"]]
        nk, nn = len(fixed_fd["failed"]), len(fixed_fd["tests"])
        L += [f"### {fd['id']} - {c['title'][lang]}", "",
              f"- **{t['f_sev']}:** {sev_label(fd['severity'], lang)}",
              f"- **{t['f_owasp']}:** {fd['owasp']}",
              f"- **{t['f_endpoint']}:** `{c['endpoint']}`",
              f"- **{t['f_scen']}:** {c['scenario'][lang]}",
              f"- **{t['f_tests']}:** {len(fd['failed'])}/{len(fd['tests'])} (" + ", ".join(f"`{x['name']}`" for x in fd["failed"]) + ")",
              "", f"**{t['f_repro']}**", "", "```bash", c["curl"], "```", "",
              f"**{t['f_evid']}**", ""]
        for ft in fd["failed"][: (1 if fd["id"] == "F6" else 2)]:
            L += [f"`{ft['name']}`:", "", "```http", evidence(ft), "```", "", f"> {ft['message'][:220]}", ""]
        if fd["id"] == "F6":
            L += [t["acc_hdr"]]
            for ft in fd["failed"]:
                resp = json.loads(ft["exchanges"][-1]["body"])
                spec = ft["message"].split("spec ")[-1].split()[0]
                diff = (int(resp["total"].replace(".", "")) - int(spec.replace(".", ""))) / 100
                L.append(f"| `{ft['params'].get('items')}` | {resp['subtotal']} | {spec} | {resp['total']} | {diff:+.2f} |")
            L.append("")
        L += [
              f"**{t['f_impact']}:** {c['impact'][lang]}", "",
              f"**{t['f_fix']}:** {c['fix'][lang]}", "", "```python", c["snippet"], "```", "",
              f"**{t['f_retest']}:** " + (t["retest_ok"].format(n=nn) if nk == 0 else t["retest_bad"].format(k=nk, n=nn)), ""]
    rows = matrix_rows(v, f)
    L += [f"## 5. {t['matrix']}", "", t["m_sum"].format(n=len(rows), vf=sum(r[5] != "passed" for r in rows), ff=sum(r[7] != "passed" for r in rows)), "", t["m_hdr"]]
    for role, method, path, exp, va, vo, fa, fo in rows:
        mark = lambda o: f"**{ok(o)}**" if o != "passed" else ok(o)  # noqa: E731
        L.append(f"| {role} | {method} | `{path}` | {exp} | {va} | {mark(vo)} | {fa} | {mark(fo)} |")
    L += ["", f"## 6. {t['functional']}", "", t["fn_hdr"]]
    fmap = {x["nodeid"]: x for x in f["tests"]}
    for x in v["tests"]:
        if x["kind"] == "functional":
            L.append(f"| `{x['name']}` | {ok(x['outcome'])} | {ok(fmap[x['nodeid']]['outcome'])} |")
    L += ["", f"## 7. {t['retest']}", "", t["r_hdr"]]
    for fid in sorted(vs["findings"]):
        a, b = vs["findings"][fid], fs["findings"][fid]
        L.append(f"| {fid} | {CATALOG[fid]['title'][lang]} | {sev_label(a['severity'], lang)} | "
                 f"{t['before'].format(k=len(a['failed']), n=len(a['tests']))} | "
                 + (t["after_ok"].format(n=len(b["tests"])) if not b["failed"] else t["after_bad"].format(k=len(b["failed"]), n=len(b["tests"]))) + " |")
    L.append(t["r_tot"].format(vf=vs["failed"], ff=fs["failed"], n=vs["total"]))
    L += ["", f"## 8. {t['repro']}", "", t["repro_txt"], "", "---", "", f"*{t['footer']}*", ""]
    return "\n".join(L)


def main() -> int:
    (ROOT / "runs").mkdir(exist_ok=True)
    (ROOT / "reports").mkdir(exist_ok=True)
    v, f = run("vulnerable"), run("fixed")
    vs, fs = stats(v), stats(f)
    for lang in ("en", "zh"):
        (ROOT / "reports" / f"sample-report.{lang}.md").write_text(build(lang, v, f, vs, fs))
    summary = {"tests_total": vs["total"], "vulnerable_failed": vs["failed"], "fixed_failed": fs["failed"],
               "findings_open_vulnerable": len(vs["open"]), "findings_open_fixed": len(fs["open"]),
               "by_severity": {s: vs["sev"].get(s, 0) for s in SEVERITIES},
               "runtime_s": {"vulnerable": vs["duration"], "fixed": fs["duration"]}}
    (ROOT / "runs" / "summary.json").write_text(json.dumps(summary, indent=1))
    print(json.dumps(summary, indent=1))
    return 0 if fs["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
