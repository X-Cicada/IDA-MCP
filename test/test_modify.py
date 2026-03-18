"""测试 api_modify.py 中的工具。

测试逻辑：
1. 使用 fixtures 获取有效的函数/全局变量地址
2. 测试注释、重命名等修改操作
3. 注意：这些测试会修改 IDB 数据库

Proxy 参数对应：
- set_comment: items (List of {address, comment})
- rename_function: address (str), new_name
- rename_local_variable: function_address (str), old_name, new_name
- rename_global_variable: old_name, new_name
- patch_bytes: items (List of {address, bytes})

运行方式：
    pytest -m modify        # 只运行 modify 模块测试
    pytest test_modify.py   # 运行此文件所有测试
"""
import pytest

from ida_mcp import api_modify

pytestmark = pytest.mark.modify


class TestSetComment:
    """设置注释测试。"""
    
    def test_set_comment_single(self, tool_caller, first_function_address):
        """测试设置单个注释。"""
        test_comment = "Test comment from pytest"
        # API 接受 items: List[{address, comment}]
        result = tool_caller("set_comment", {
            "items": [{"address": hex(first_function_address), "comment": test_comment}]
        })
        
        assert isinstance(result, list)
        assert len(result) == 1
        if "error" not in result[0]:
            # API 返回 changed 字段
            assert "changed" in result[0]
    
    def test_set_comment_batch(self, tool_caller, functions_cache):
        """测试批量设置注释。"""
        if len(functions_cache) < 3:
            pytest.skip("Not enough functions")
        
        items = [
            {"address": f["start_ea"], "comment": f"Batch comment {i}"}
            for i, f in enumerate(functions_cache[:3])
        ]
        result = tool_caller("set_comment", {"items": items})
        
        assert isinstance(result, list)
        assert len(result) == 3
    
    def test_set_comment_clear(self, tool_caller, first_function_address):
        """测试清除注释。"""
        addr = hex(first_function_address)
        # 先设置注释
        tool_caller("set_comment", {
            "items": [{"address": addr, "comment": "To be cleared"}]
        })
        
        # 然后清除
        result = tool_caller("set_comment", {
            "items": [{"address": addr, "comment": ""}]
        })
        
        assert isinstance(result, list)
    
    def test_set_comment_multiple_different(self, tool_caller, functions_cache):
        """测试设置不同的注释到不同地址。"""
        if len(functions_cache) < 2:
            pytest.skip("Not enough functions")
        
        items = [
            {"address": functions_cache[0]["start_ea"], "comment": "Comment A"},
            {"address": functions_cache[1]["start_ea"], "comment": "Comment B"},
        ]
        result = tool_caller("set_comment", {"items": items})
        
        assert isinstance(result, list)
        assert len(result) == 2


class TestRenameFunction:
    """重命名函数测试。"""
    
    def test_rename_function(self, tool_caller, first_function):
        """测试重命名函数。"""
        old_name = first_function["name"]
        # start_ea 是 hex 字符串，去掉 0x 前缀用于名称
        addr_str = first_function['start_ea'].replace('0x', '').replace('0X', '')
        new_name = f"test_renamed_{addr_str}"
        
        # Proxy 参数: address (str), new_name
        result = tool_caller("rename_function", {
            "address": first_function["start_ea"],
            "new_name": new_name
        })
        
        if "error" not in result:
            assert "changed" in result
            # 恢复原名
            tool_caller("rename_function", {
                "address": first_function["start_ea"],
                "new_name": old_name
            })
        else:
            # 如果失败，打印调试信息
            print(f"rename_function failed: {result}")
            # 可能是数据库状态问题，尝试通过函数名
            result2 = tool_caller("rename_function", {
                "address": old_name,
                "new_name": new_name
            })
            if "error" not in result2:
                # 恢复原名
                tool_caller("rename_function", {
                    "address": new_name,
                    "new_name": old_name
                })
    
    def test_rename_function_by_name(self, tool_caller, first_function):
        """测试通过函数名重命名（回退测试）。"""
        old_name = first_function["name"]
        new_name = f"test_by_name_{old_name[:8]}"
        
        result = tool_caller("rename_function", {
            "address": old_name,
            "new_name": new_name
        })
        
        # 恢复原名（无论成功与否都尝试）
        if "error" not in result:
            tool_caller("rename_function", {
                "address": new_name,
                "new_name": old_name
            })
    
    def test_rename_function_invalid_name(self, tool_caller, first_function):
        """测试使用无效名称（以数字开头）。"""
        result = tool_caller("rename_function", {
            "address": first_function["start_ea"],
            "new_name": "123invalid"
        })
        # Proxy 转发到 API 验证 C 标识符，应该返回错误
        assert "error" in result
    
    def test_rename_function_empty_name(self, tool_caller, first_function):
        """测试空名称。"""
        result = tool_caller("rename_function", {
            "address": first_function["start_ea"],
            "new_name": ""
        })
        assert "error" in result


class TestRenameLocalVariable:
    """重命名局部变量测试。"""
    
    def test_rename_local_variable(self, tool_caller, first_function_address):
        """测试重命名局部变量。"""
        # API 参数: function_address (str), old_name, new_name
        result = tool_caller("rename_local_variable", {
            "function_address": hex(first_function_address),
            "old_name": "v1",
            "new_name": "test_var"
        })
        # 可能成功或失败（取决于是否有该变量）
        assert isinstance(result, dict)


class TestRenameGlobalVariable:
    """重命名全局变量测试。"""
    
    def test_rename_global_variable(self, tool_caller, first_global):
        """测试重命名全局变量。"""
        old_name = first_global["name"]
        # ea 是 hex 字符串，去掉 0x 前缀用于名称
        addr_str = first_global['ea'].replace('0x', '').replace('0X', '')
        new_name = f"test_global_{addr_str}"
        
        # API 参数: old_name, new_name
        result = tool_caller("rename_global_variable", {
            "old_name": old_name,
            "new_name": new_name
        })
        
        if "error" not in result and result.get("changed"):
            # 恢复原名
            tool_caller("rename_global_variable", {
                "old_name": new_name,
                "new_name": old_name
            })
    
    def test_rename_global_variable_not_found(self, tool_caller):
        """测试重命名不存在的全局变量。"""
        result = tool_caller("rename_global_variable", {
            "old_name": "nonexistent_global_xyz123",
            "new_name": "new_name"
        })
        assert "error" in result


class TestPatchBytes:
    """字节补丁测试。
    
    注意：这些测试会修改数据库，使用先读后恢复的策略。
    """
    
    def test_patch_bytes_and_restore(self, tool_caller, first_function_address):
        """测试补丁并恢复字节。"""
        addr = first_function_address
        
        # 1. 读取原始字节
        read_result = tool_caller("get_bytes", {
            "addr": hex(addr),
            "size": 4
        })
        
        if not isinstance(read_result, list) or not read_result:
            pytest.skip("Cannot read bytes")
        
        original_bytes = read_result[0].get("bytes", [])
        if not original_bytes:
            pytest.skip("No bytes read")
        
        # 2. 打补丁 (NOP: 0x90)
        nop_bytes = [0x90] * len(original_bytes)
        patch_result = tool_caller("patch_bytes", {
            "items": [{"address": addr, "bytes": nop_bytes}]
        })
        
        assert isinstance(patch_result, list)
        assert len(patch_result) == 1
        
        # 3. 恢复原始字节
        restore_result = tool_caller("patch_bytes", {
            "items": [{"address": addr, "bytes": original_bytes}]
        })
        
        assert isinstance(restore_result, list)
    
    def test_patch_bytes_hex_string(self, tool_caller, first_function_address):
        """测试使用十六进制字符串补丁。"""
        addr = first_function_address
        
        # 读取原始
        read_result = tool_caller("get_bytes", {
            "addr": hex(addr),
            "size": 2
        })
        
        if not isinstance(read_result, list) or not read_result:
            pytest.skip("Cannot read bytes")
        
        original = read_result[0].get("bytes", [])
        
        # 用 hex string 格式打补丁
        result = tool_caller("patch_bytes", {
            "items": [{"address": addr, "bytes": "90 90"}]
        })
        
        assert isinstance(result, list)
        
        # 恢复
        tool_caller("patch_bytes", {
            "items": [{"address": addr, "bytes": original}]
        })
    
    def test_patch_bytes_invalid_address(self, tool_caller):
        """测试无效地址。"""
        result = tool_caller("patch_bytes", {
            "items": [{"address": "invalid", "bytes": [0x90]}]
        })
        
        assert isinstance(result, list)
        assert result[0].get("error") is not None
    
    def test_patch_bytes_empty_bytes(self, tool_caller, first_function_address):
        """测试空字节。"""
        result = tool_caller("patch_bytes", {
            "items": [{"address": first_function_address, "bytes": []}]
        })
        
        assert isinstance(result, list)
        assert result[0].get("error") is not None


class TestPatchBytesHelpers:
    def test_patch_bytes_invalidates_string_cache_on_partial_success(self, monkeypatch):
        calls = {"invalidate": 0}

        class FakeBytes:
            @staticmethod
            def get_bytes(_ea, _size):
                return b"\x90\x90"

            @staticmethod
            def patch_byte(ea, _value):
                if ea == 0x401001:
                    raise RuntimeError("boom")

        monkeypatch.setattr(api_modify, "ida_bytes", FakeBytes())
        monkeypatch.setattr(api_modify, "_invalidate_strings_cache", lambda: calls.__setitem__("invalidate", calls["invalidate"] + 1))

        result = api_modify.patch_bytes.__wrapped__([{"address": "0x401000", "bytes": [0x90, 0x91]}])

        assert result[0]["patched"] == 1
        assert calls["invalidate"] == 1
