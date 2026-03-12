"""IDA MCP 代理模块。

提供通过协调器访问多个 IDA 实例的 MCP 代理服务。

架构:
- _server.py: 共享的 FastMCP server（唯一的工具定义源）
- ida_mcp_proxy.py: stdio 传输入口
- http_server.py: HTTP 传输入口（复用同一个 server）

使用方式:
    # stdio 模式
    python -m ida_mcp.proxy.ida_mcp_proxy
    
    # HTTP 模式（由协调器自动启动）
    from ida_mcp.proxy.http_server import start_http_proxy

导入:
    from ida_mcp.proxy import server
"""
from __future__ import annotations

from ._server import server
from .http_server import get_http_url, is_http_proxy_running, start_http_proxy, stop_http_proxy

__all__ = ['server', 'start_http_proxy', 'stop_http_proxy', 'is_http_proxy_running', 'get_http_url']

