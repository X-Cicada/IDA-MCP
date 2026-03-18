"""测试 api_memory.py 中的工具。

测试逻辑：
1. 使用 fixtures 获取有效地址（函数/字符串）
2. 测试读取字节/整数/字符串

API 参数对应 (IDA API 工具名):
- get_bytes: addr (逗号分隔), size
- read_scalar: addr (逗号分隔), width, signed
- get_string: addr (逗号分隔), max_len

运行方式：
    pytest -m memory        # 只运行 memory 模块测试
    pytest test_memory.py   # 运行此文件所有测试
"""
import pytest

pytestmark = pytest.mark.memory


class TestGetBytes:
    """读取字节测试。"""
    
    def test_get_bytes_from_function(self, tool_caller, first_function_address):
        """测试从函数地址读取字节。"""
        result = tool_caller("get_bytes", {
            "addr": hex(first_function_address),
            "size": 16
        })
        
        # API 返回列表格式 [{"addr": ..., "hex": ..., "bytes": ...}]
        assert isinstance(result, list)
        assert len(result) >= 1
        if "error" not in result[0]:
            assert "bytes" in result[0] or "hex" in result[0]
    
    def test_get_bytes_different_sizes(self, tool_caller, first_function_address):
        """测试不同大小。"""
        for size in [1, 4, 16, 64, 256]:
            result = tool_caller("get_bytes", {
                "addr": hex(first_function_address),
                "size": size
            })
            assert isinstance(result, list)
            if result and "error" not in result[0]:
                # API 返回 hex 字段，格式为 "XX XX XX"（空格分隔）
                hex_str = result[0].get("hex", "")
                # 去除空格后，每字节2个hex字符
                hex_clean = hex_str.replace(" ", "")
                assert len(hex_clean) == size * 2
    
    def test_get_bytes_batch(self, tool_caller, functions_cache):
        """测试批量读取字节（逗号分隔）。"""
        if len(functions_cache) < 3:
            pytest.skip("Not enough functions for batch test")
        
        addr_list = ",".join(f["start_ea"] for f in functions_cache[:3])
        result = tool_caller("get_bytes", {
            "addr": addr_list,
            "size": 8
        })
        
        assert isinstance(result, list)
        assert len(result) == 3


class TestReadScalar:
    """读取标量测试。"""

    def test_read_scalar_u32(self, tool_caller, first_function_address):
        """测试读取 4 字节无符号整数。"""
        result = tool_caller("read_scalar", {"addr": hex(first_function_address), "width": 4})

        assert isinstance(result, list)
        assert len(result) >= 1
        if "error" not in result[0]:
            assert "value" in result[0]
            assert result[0]["width"] == 4
            assert result[0]["signed"] is False
            assert 0 <= result[0]["value"] <= 0xFFFFFFFF

    def test_read_scalar_u64(self, tool_caller, first_function_address):
        """测试读取 8 字节无符号整数。"""
        result = tool_caller("read_scalar", {"addr": hex(first_function_address), "width": 8})

        assert isinstance(result, list)
        assert len(result) >= 1
        if "error" not in result[0]:
            assert "value" in result[0]
            assert result[0]["width"] == 8

    def test_read_scalar_u8(self, tool_caller, first_function_address):
        """测试读取 1 字节无符号整数。"""
        result = tool_caller("read_scalar", {"addr": hex(first_function_address), "width": 1})

        assert isinstance(result, list)
        assert len(result) >= 1
        if "error" not in result[0]:
            assert "value" in result[0]
            assert result[0]["width"] == 1
            assert 0 <= result[0]["value"] <= 255

    def test_read_scalar_u16(self, tool_caller, first_function_address):
        """测试读取 2 字节无符号整数。"""
        result = tool_caller("read_scalar", {"addr": hex(first_function_address), "width": 2})

        assert isinstance(result, list)
        assert len(result) >= 1
        if "error" not in result[0]:
            assert "value" in result[0]
            assert result[0]["width"] == 2
            assert 0 <= result[0]["value"] <= 0xFFFF

    def test_read_scalar_rejects_invalid_width(self, tool_caller, first_function_address):
        """测试拒绝不支持的宽度。"""
        result = tool_caller("read_scalar", {"addr": hex(first_function_address), "width": 3})

        assert isinstance(result, list)
        assert len(result) >= 1
        assert "error" in result[0]


class TestGetString:
    """读取字符串测试。"""
    
    def test_get_string(self, tool_caller, first_string_address):
        """测试读取字符串。"""
        result = tool_caller("get_string", {"addr": hex(first_string_address)})
        
        # API 返回列表格式
        assert isinstance(result, list)
        assert len(result) >= 1
        if "error" not in result[0]:
            assert "text" in result[0] or "value" in result[0]
    
    def test_get_string_with_max_length(self, tool_caller, first_string_address):
        """测试带最大长度限制。"""
        result = tool_caller("get_string", {
            "addr": hex(first_string_address),
            "max_len": 5
        })
        
        assert isinstance(result, list)
        assert len(result) >= 1
        if "error" not in result[0]:
            text = result[0].get("text") or result[0].get("value", "")
            # max_len 限制返回长度
            if text:
                assert len(text) <= 5
    
    def test_get_string_from_code(self, tool_caller, first_function_address):
        """测试从代码地址读取（应该返回非空但可能乱码）。"""
        result = tool_caller("get_string", {"addr": hex(first_function_address)})
        
        assert isinstance(result, list)
        # 代码区域通常不是有效字符串，但 API 会尝试读取
    
    def test_get_string_batch(self, tool_caller, strings_cache):
        """测试批量读取字符串（逗号分隔）。"""
        if len(strings_cache) < 3:
            pytest.skip("Not enough strings")
        
        # strings_cache 中 ea 可能是整数或字符串
        addr_list = ",".join(
            hex(s["ea"]) if isinstance(s["ea"], int) else s["ea"] 
            for s in strings_cache[:3]
        )
        result = tool_caller("get_string", {"addr": addr_list})
        
        assert isinstance(result, list)
        assert len(result) == 3
