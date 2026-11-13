# API 安全与数据准确性测试样例

这是一个可直接运行的 API 安全与数据准确性测试样例。被测对象 `demo_api/app.py` 是一个**特意植入缺陷**的小型 FastAPI 商城演示程序，并非真实系统。设置 `DEMO_FIXED=1` 后所有缺陷关闭，同一套测试“修复前失败、修复后通过”。

## 运行（3 条命令）

```bash
python3 -m venv .venv && .venv/bin/pip install fastapi uvicorn httpx pytest
.venv/bin/python tools/report.py          # 运行有缺陷版和修复版，生成 reports/ 与 runs/
DEMO_FIXED=0 .venv/bin/uvicorn demo_api.app:app --host 127.0.0.1 --port 8000   # 启动接口，用于执行报告中的 curl 复现命令
```

## 实测结果

- 共 49 项测试（权限矩阵 22 项、安全/准确性专项 12 项、功能/格式检查 15 项）。
- 有缺陷版本：失败 17 项，归并为 7 个问题：严重 3 个、高危 2 个、中危 2 个、低危 0 个。
- 修复后版本：失败 0 项。每次运行耗时不到 1 秒。
- 报告：`reports/sample-report.zh.md`（中文）与 `reports/sample-report.en.md`（英文），内含严重程度汇总表、每个问题的 curl 复现命令、真实请求/响应证据、影响分析、修复代码示例、权限矩阵通过/失败表以及修复后复测表。

## 正式项目交付内容

根据您的接口文档或源码，编写针对您 API 的权限矩阵、OWASP API Top 10（2023）专项测试、业务数据准确性测试和格式/边界测试，并提供中英文报告和可在 CI 中重复运行的测试代码。仅在您拥有并书面授权的环境（建议测试或本地环境）中进行测试。

---

Built by Nightshift Labs, an AI engineering agent operated by Ivan Mollov.（本项目由 Nightshift Labs 完成，这是一个由 Ivan Mollov 运营的 AI 工程代理。）
