"""测试调试器相关工具。

测试前提：
1. 调试器类型已在 IDA 中手动配置好
2. 如有 PDB 对话框弹出，手动关闭

测试顺序：
1. Phase 0: 断点管理（不需要调试器运行）
2. Phase 1: 启动调试器
3. Phase 2: 状态检查
4. Phase 3: 单步执行
5. Phase 9: 清理

运行方式：
    pytest -m debug         # 只运行 debug 模块测试
    pytest test_debug.py    # 运行此文件所有测试
"""
import pytest
import time
from typing import Optional

from ida_mcp import api_debug

pytestmark = pytest.mark.debug


class DebugState:
    """调试器状态跟踪。"""
    breakpoint_address: Optional[int] = None
    debugger_started: bool = False


class TestDebug0_Breakpoints:
    """Phase 0: 断点管理。"""
    
    def test_00_list_breakpoints(self, tool_caller):
        """列出断点。"""
        result = tool_caller("dbg_list_bps")
        assert isinstance(result, dict)
        print(f"Breakpoints: {result}")
    
    def test_01_set_breakpoint(self, tool_caller, main_function, first_function_address):
        """设置断点。"""
        if main_function:
            addr = int(main_function["start_ea"], 16) if isinstance(main_function["start_ea"], str) else main_function["start_ea"]
        else:
            addr = first_function_address
        
        DebugState.breakpoint_address = addr
        
        result = tool_caller("dbg_add_bp", {"addr": addr})
        assert isinstance(result, list)
        print(f"Set breakpoint at {hex(addr)}: {result}")
    
    def test_02_list_breakpoints_after_set(self, tool_caller):
        """设置后列出断点。"""
        result = tool_caller("dbg_list_bps")
        assert isinstance(result, dict)
        print(f"Breakpoints: {result}")
    
    def test_03_enable_breakpoint(self, tool_caller):
        """启用断点。"""
        if not DebugState.breakpoint_address:
            pytest.skip("No breakpoint")
        
        result = tool_caller("dbg_enable_bp", {
            "items": [{"address": DebugState.breakpoint_address, "enable": True}]
        })
        assert isinstance(result, list)
        print(f"Enable: {result}")


class TestDebug1_Start:
    """Phase 1: 启动调试器。"""
    
    def test_10_start_debugger(self, tool_caller):
        """启动调试器。"""
        result = tool_caller("dbg_start")
        assert isinstance(result, dict)
        print(f"Start: {result}")
        
        if result.get("ok") or result.get("started"):
            DebugState.debugger_started = True
    
    def test_11_verify_state(self, tool_caller):
        """验证调试器状态。"""
        result = tool_caller("dbg_regs")
        assert isinstance(result, dict)
        print(f"Registers: {result}")


class TestDebug2_Inspection:
    """Phase 2: 状态检查。"""
    
    def test_20_get_registers(self, tool_caller):
        """获取寄存器。"""
        if not DebugState.debugger_started:
            pytest.skip("Debugger not started")
        
        result = tool_caller("dbg_regs")
        assert isinstance(result, dict)
        print(f"Registers: {result}")
    
    def test_21_get_call_stack(self, tool_caller):
        """获取调用栈。"""
        if not DebugState.debugger_started:
            pytest.skip("Debugger not started")
        
        result = tool_caller("dbg_callstack")
        assert isinstance(result, (dict, list))
        print(f"Call stack: {result}")


class TestDebug3_Stepping:
    """Phase 3: 单步执行。"""
    
    def test_30_step_into(self, tool_caller):
        """单步进入。"""
        if not DebugState.debugger_started:
            pytest.skip("Debugger not started")
        
        result = tool_caller("dbg_step_into")
        assert isinstance(result, dict)
        print(f"Step into: {result}")
        time.sleep(0.1)
    
    def test_31_step_over(self, tool_caller):
        """单步跳过。"""
        if not DebugState.debugger_started:
            pytest.skip("Debugger not started")
        
        result = tool_caller("dbg_step_over")
        assert isinstance(result, dict)
        print(f"Step over: {result}")
        time.sleep(0.1)


class TestDebug9_Cleanup:
    """Phase 9: 清理。"""
    
    def test_90_delete_breakpoint(self, tool_caller):
        """删除断点。"""
        if not DebugState.breakpoint_address:
            pytest.skip("No breakpoint")
        
        result = tool_caller("dbg_delete_bp", {
            "addr": DebugState.breakpoint_address
        })
        assert isinstance(result, list)
        print(f"Delete: {result}")
    
    def test_99_exit_debugger(self, tool_caller):
        """退出调试器。"""
        if not DebugState.debugger_started:
            pytest.skip("Debugger not started")
        
        result = tool_caller("dbg_exit")
        assert isinstance(result, dict)
        print(f"Exit: {result}")
        
        DebugState.debugger_started = False
        DebugState.breakpoint_address = None


class TestDebugHelpers:
    def test_dbg_run_to_cleans_temporary_breakpoint(self, monkeypatch):
        calls = {"added": 0, "deleted": 0, "continued": 0}

        class FakeDbg:
            BPT_DEFAULT = 0

            @staticmethod
            def is_debugger_on():
                return True

            @staticmethod
            def add_bpt(_addr, *_args):
                calls["added"] += 1
                return True

            @staticmethod
            def continue_process():
                calls["continued"] += 1
                return True

            @staticmethod
            def del_bpt(_addr):
                calls["deleted"] += 1
                return True

        monkeypatch.setattr(api_debug, "ida_dbg", FakeDbg())
        monkeypatch.setattr(api_debug, "idaapi", type("FakeIdaApi", (), {"BADADDR": -1})())
        monkeypatch.setattr(api_debug, "_wait_for_debugger_event", lambda _timeout=1000: True)
        monkeypatch.setattr(api_debug, "_breakpoint_exists", lambda _addr: False)

        result = api_debug.dbg_run_to.__wrapped__("0x401000")

        assert result["used_temp_bpt"] is True
        assert result["cleaned_temp_bpt"] is True
        assert calls == {"added": 1, "deleted": 1, "continued": 1}

    def test_dbg_read_mem_reports_integer_size(self, monkeypatch):
        class FakeDbg:
            @staticmethod
            def is_debugger_on():
                return True

            @staticmethod
            def read_dbg_memory(_addr, _size):
                return b"\x90\x91"

        monkeypatch.setattr(api_debug, "ida_dbg", FakeDbg())

        result = api_debug.dbg_read_mem.__wrapped__([{"address": "0x401000", "size": 2}])

        assert result[0]["size"] == 2
        assert isinstance(result[0]["size"], int)

    def test_dbg_write_mem_reports_integer_size(self, monkeypatch):
        class FakeDbg:
            @staticmethod
            def is_debugger_on():
                return True

            @staticmethod
            def write_dbg_memory(_addr, data):
                return len(data)

        monkeypatch.setattr(api_debug, "ida_dbg", FakeDbg())

        result = api_debug.dbg_write_mem.__wrapped__([{"address": "0x401000", "bytes": [0x90, 0x91]}])

        assert result[0]["size"] == 2
        assert isinstance(result[0]["size"], int)
