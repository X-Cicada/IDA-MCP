#!/usr/bin/env python
"""IDA-MCP 测试主入口。

使用方法:
    python test/test.py                 # 运行全部测试（不含 debug）
    python test/test.py --all           # 运行全部测试（含 debug）
    
    # 按模块运行:
    python test/test.py --core          # Core 模块（元数据、函数、导入导出等）
    python test/test.py --analysis      # Analysis 模块（反编译、搜索、基本块等）
    python test/test.py --types         # Types 模块（类型声明、结构体等）
    python test/test.py --modify        # Modify 模块（注释、重命名、补丁等）
    python test/test.py --modeling      # Modeling 模块（建函数、转 code/data/string）
    python test/test.py --memory        # Memory 模块（读取字节/整数/字符串）
    python test/test.py --stack         # Stack 模块（栈帧变量）
    python test/test.py --debug         # Debug 模块（调试器，需手动配置）
    python test/test.py --resources     # Resources 模块（MCP 资源）
    python test/test.py --lifecycle     # Lifecycle 模块（启动/关闭 IDA）
    
    # 传输模式:
    python test/test.py --transport=stdio    # 只测试 stdio 模式
    python test/test.py --transport=http     # 只测试 HTTP 模式
    python test/test.py --transport=both     # 测试两种模式（默认）
    
    # 组合使用:
    python test/test.py --core --analysis    # 运行 core 和 analysis
    python test/test.py --transport=http --analysis  # HTTP 模式下运行 analysis
    
    # 直接使用 pytest:
    pytest -m core                      # 只运行 core 模块
    pytest -m "core or analysis"        # 运行 core 和 analysis
    pytest -m "not debug"               # 排除 debug 模块
    pytest --transport=http             # 只测试 HTTP 模式
    pytest test/test_core.py            # 运行指定文件
"""
import sys
import os

# 添加项目根目录到路径
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# 可用的模块 markers
MODULES = ["core", "analysis", "types", "modify", "modeling", "memory", "stack", "debug", "resources", "lifecycle"]

GATEWAY_HOST = "127.0.0.1"
GATEWAY_PORT = 11338
GATEWAY_INTERNAL_BASE = f"http://{GATEWAY_HOST}:{GATEWAY_PORT}/internal"


def check_gateway() -> bool:
    """检查 gateway internal API 是否可用。"""
    import urllib.request
    import json
    
    try:
        url = f"{GATEWAY_INTERNAL_BASE}/healthz"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=2) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            return bool(isinstance(data, dict) and data.get("ok"))
    except Exception:
        return False


def check_instances_available() -> bool:
    """检查是否已有已注册的 IDA 实例。"""
    import urllib.request
    import json

    try:
        url = f"{GATEWAY_INTERNAL_BASE}/instances"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=2) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            instances = data if isinstance(data, list) else []
            return len(instances) > 0
    except Exception:
        return False


def check_http_proxy() -> bool:
    """检查 HTTP 代理是否可用。"""
    import socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((GATEWAY_HOST, GATEWAY_PORT))
        sock.close()
        return result == 0
    except Exception:
        return False


def print_help():
    """打印帮助信息。"""
    print(__doc__)
    print("可用模块:")
    for m in MODULES:
        print(f"  --{m}")
    print()


def run_tests(args: list | None = None):
    """运行测试。"""
    try:
        import pytest
    except ImportError:
        print("ERROR: pytest not installed. Run: pip install pytest")
        return 1
    
    # 检查 gateway / 实例可用性
    if not check_gateway():
        print(f"WARNING: Gateway internal API not available at {GATEWAY_INTERNAL_BASE}")
        print("Please start IDA and load the MCP plugin first.")
        print()
        response = input("Continue anyway? (y/N): ").strip().lower()
        if response != 'y':
            return 1
    elif not check_instances_available():
        print("WARNING: No IDA instances available.")
        print("Please open a binary in IDA and ensure the MCP plugin is running.")
        print()
        response = input("Continue anyway? (y/N): ").strip().lower()
        if response != 'y':
            return 1
    
    # 构建 pytest 参数
    test_dir = os.path.dirname(os.path.abspath(__file__))
    pytest_args = [test_dir, "-v"]
    
    # 收集要运行的模块
    selected_modules: list[str] = []
    run_all = False
    transport_mode = "both"  # 默认测试两种模式
    remaining_args: list[str] = []
    
    if args:
        for arg in args:
            if arg == "--all":
                run_all = True
            elif arg.startswith("--transport="):
                transport_mode = arg.split("=", 1)[1]
            elif arg.startswith("--") and arg[2:] in MODULES:
                selected_modules.append(arg[2:])
            else:
                remaining_args.append(arg)
    
    # 添加 transport 参数
    pytest_args.extend([f"--transport={transport_mode}"])
    
    # 检查 HTTP 代理（如果需要）
    if transport_mode in ("http", "both"):
        if not check_http_proxy():
            print(f"WARNING: HTTP proxy not available at {GATEWAY_HOST}:{GATEWAY_PORT}")
            if transport_mode == "http":
                print("Please check config.conf and restart IDA plugin.")
                return 1
            else:
                print("HTTP tests will be skipped.")
    
    # 构建 marker 表达式
    if selected_modules:
        # 运行指定模块
        marker_expr = " or ".join(selected_modules)
        pytest_args.extend(["-m", marker_expr])
    elif not run_all:
        # 默认排除 debug（需要手动配置调试器）
        pytest_args.extend(["-m", "not debug"])
    
    # 传递其他参数给 pytest
    pytest_args.extend(remaining_args)
    
    # 显示将要运行的测试
    print(f"Transport mode: {transport_mode}")
    print(f"Running: pytest {' '.join(pytest_args[1:])}")
    print()
    
    # 运行测试
    return pytest.main(pytest_args)


def main():
    """主函数。"""
    args = sys.argv[1:]
    
    if "--help" in args or "-h" in args:
        print_help()
        return 0
    
    return run_tests(args)


if __name__ == "__main__":
    sys.exit(main())
