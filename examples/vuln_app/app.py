"""演示用样例应用 -- 植入若干疑似漏洞点，供黑板报机制扫描分析。

预期（mock 启发式）：
- 确认漏洞：SQL 注入、命令注入、eval 执行用户输入、pickle 反序列化、硬编码口令
- 误报：常量参数的危险调用（参数无外部输入可达）
- 待复核：参数含变量但未明显溯源到输入源
- 真阴性（不上板）：参数化查询
"""

import os
import pickle
import subprocess

from flask import Flask, request

app = Flask(__name__)
PASSWORD = "s3cr3t-pw"  # 硬编码口令


@app.route("/login")
def login():
    name = request.args.get("name", "")
    # 疑似 SQL 注入（f-string 拼接用户输入）
    cur = app.config["db"].cursor()
    cur.execute(f"SELECT * FROM users WHERE name='{name}'")
    return cur.fetchone() or ("", 404)


@app.route("/safe")
def safe():
    # 参数化查询：不拼字符串，scanner 不会上板（真阴性）
    uid = request.args.get("id", "0")
    cur = app.config["db"].cursor()
    cur.execute("SELECT * FROM users WHERE id=?", (uid,))
    return cur.fetchone() or ("", 404)


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    os.system("ping -c 1 " + host)  # 命令注入
    return "ok"


@app.route("/calc")
def calc():
    expr = request.args.get("expr", "")
    return str(eval(expr))  # eval 用户输入 -> RCE


@app.route("/static-calc")
def static_calc():
    return str(eval("1+1"))  # 常量参数 -> 误报


@app.route("/load")
def load():
    data = request.get_data()
    pickle.loads(data)  # 反序列化
    return "ok"


@app.route("/echo")
def echo():
    os.system("echo hello")  # 常量命令 -> 误报
    return "ok"


@app.route("/run")
def run():
    tool = os.environ.get("TOOL", "ls")
    os.system(tool)  # 变量但非明显输入源 -> 待复核
    return "ok"


if __name__ == "__main__":
    app.run()
