"""类型 API - 类型操作。

提供工具:
    - declare_type         声明/更新类型
    - set_function_prototype  设置函数原型
    - set_local_variable_type 设置局部变量类型
    - set_global_variable_type 设置全局变量类型
    - list_structs         列出结构体
    - get_struct_info      获取结构体详情
"""
from __future__ import annotations

import sys
from typing import Annotated, Optional, List, Dict, Any, Union

from .compat import get_idati as _get_idati
from .rpc import tool
from .sync import idaread, idawrite
from .utils import parse_address, is_valid_c_identifier, hex_addr

# IDA 模块导入
import idaapi  # type: ignore
import ida_funcs  # type: ignore
import ida_typeinf  # type: ignore
import ida_hexrays  # type: ignore

# PT_SIL = 1: 静默解析，不显示语法错误对话框
PT_SIL = getattr(ida_typeinf, 'PT_SIL', 1)
# PT_TYP = 2: 解析类型声明 (struct/union/enum/typedef)
PT_TYP = getattr(ida_typeinf, 'PT_TYP', 2)
# PT_EMPTY = 0x4000: 允许空声明
PT_EMPTY = getattr(ida_typeinf, 'PT_EMPTY', 0x4000)


# ============================================================================
# 类型声明辅助函数
# ============================================================================

def _parse_decls_ctypes(decls: str, hti_flags: int) -> tuple:
    """使用 ctypes 调用 parse_decls (仅 Windows)。
    
    返回:
        (errors: int, messages: List[str])
    """
    if sys.platform != "win32":
        return (-1, ["parse_decls_ctypes only supported on Windows"])
    
    try:
        import ctypes
        
        c_decls = decls.encode("utf-8")
        c_til = None
        ida_dll = ctypes.CDLL("ida")
        ida_dll.parse_decls.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_void_p,
            ctypes.c_int,
        ]
        ida_dll.parse_decls.restype = ctypes.c_int
        
        messages: List[str] = []
        
        @ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p)
        def magic_printer(fmt: bytes, arg1: bytes):
            if fmt.count(b"%") == 1 and b"%s" in fmt:
                formatted = fmt.replace(b"%s", arg1)
                messages.append(formatted.decode("utf-8", errors="replace"))
                return len(formatted) + 1
            else:
                messages.append(f"unsupported magic_printer fmt: {repr(fmt)}")
                return 0
        
        errors = ida_dll.parse_decls(c_til, c_decls, magic_printer, hti_flags)
        return (errors, messages)
    except Exception as e:
        return (-1, [str(e)])


def _parse_decls_python(decls: str, hti_flags: int) -> tuple:
    """使用 IDAPython API 调用 parse_decls。
    
    返回:
        (errors: int, messages: List[str])
    """
    try:
        # ida_typeinf.parse_decls(til, input, printer, hti_flags)
        # 使用默认类型库
        errors = ida_typeinf.parse_decls(ida_typeinf.get_idati(), decls, False, hti_flags)
        return (errors, [])
    except Exception as e:
        return (-1, [str(e)])


# ============================================================================
# 类型声明
# ============================================================================

@tool
@idawrite
def declare_type(
    decl: Annotated[str, "C type declaration (struct/union/enum/typedef)"],
) -> dict:
    """Declare C type(s) in the local type library."""
    if not decl or not decl.strip():
        return {"error": "empty declaration"}
    
    decl_text = decl.strip()
    
    # 使用 parse_decls 直接解析并添加到类型库
    # 这比 parse_decl + set_named_type 更可靠
    hti_flags = PT_SIL | PT_TYP | PT_EMPTY
    
    # 尝试 ctypes 方式 (Windows)
    errors, messages = _parse_decls_ctypes(decl_text, hti_flags)
    
    # 如果 ctypes 失败，尝试 Python API
    if errors < 0:
        errors, messages = _parse_decls_python(decl_text, hti_flags)
    
    if errors > 0:
        return {
            "error": f"parse failed ({errors} errors)",
            "details": messages[:5] if messages else [],
        }
    elif errors < 0:
        # 两种方法都失败，回退到旧方法
        return _declare_type_fallback(decl_text)
    
    return {
        "decl": decl_text,
        "ok": True,
        "messages": messages[:5] if messages else None,
    }


def _declare_type_fallback(decl_text: str) -> dict:
    """declare_type 的回退实现 (使用 parse_decl + set_named_type)。"""
    tinfo = ida_typeinf.tinfo_t()
    name = None
    parse_errors: List[str] = []
    
    variants = [
        ("idaapi.parse_decl", lambda: idaapi.parse_decl(tinfo, _get_idati(), decl_text, PT_SIL)),  # type: ignore
        ("ida_typeinf.parse_decl", lambda: ida_typeinf.parse_decl(tinfo, _get_idati(), decl_text, PT_SIL)),  # type: ignore
    ]
    
    for label, fn in variants:
        try:
            nm = fn()
            if isinstance(nm, (list, tuple)) and nm:
                nm = nm[0]
            if isinstance(nm, str) and nm:
                name = nm
            if tinfo and not tinfo.empty():
                break
        except Exception as e:
            parse_errors.append(f"{label}: {e}")
    
    if not name or not tinfo or tinfo.empty():
        return {"error": "parse failed", "details": parse_errors[:2]}
    
    # 检查是否已存在
    existed = False
    try:
        existed = bool(ida_typeinf.get_named_type(_get_idati(), name, 0))  # type: ignore
    except Exception:
        existed = False
    
    # 设置类型 - 尝试多种方法
    ok = False
    set_errors: List[str] = []
    
    # 方法 1: set_named_type
    try:
        flags = getattr(ida_typeinf, 'NTF_REPLACE', 0) if existed else 0
        ok = bool(ida_typeinf.set_named_type(_get_idati(), name, flags, tinfo, 0))  # type: ignore
    except AttributeError as e:
        set_errors.append(f"set_named_type: {e}")
    except Exception as e:
        set_errors.append(f"set_named_type: {e}")
    
    # 方法 2: tinfo_t.set_named_type (IDA 9.x)
    if not ok:
        try:
            ok = bool(tinfo.set_named_type(None, name, ida_typeinf.NTF_REPLACE if existed else 0))  # type: ignore
        except AttributeError:
            pass
        except Exception as e:
            set_errors.append(f"tinfo.set_named_type: {e}")
    
    if not ok:
        return {"error": "set type failed", "details": set_errors[:2]}
    
    kind = "other"
    try:
        if tinfo.is_struct():
            kind = "struct"
        elif tinfo.is_union():
            kind = "union"
        elif tinfo.is_enum():
            kind = "enum"
        elif tinfo.is_typedef():
            kind = "typedef"
    except Exception:
        pass
    
    return {
        "name": name,
        "kind": kind,
        "replaced": bool(existed),
        "success": bool(ok),
    }


# ============================================================================
# 函数原型
# ============================================================================

@tool
@idawrite
def set_function_prototype(
    function_address: Annotated[Union[int, str], "Function start or internal address (hex or decimal)"],
    prototype: Annotated[str, "Full C function declaration"],
) -> dict:
    """Set function prototype (type signature)."""
    if function_address is None:
        return {"error": "invalid function_address"}
    if not prototype or not prototype.strip():
        return {"error": "empty prototype"}
    
    parsed = parse_address(str(function_address))
    if not parsed["ok"] or parsed["value"] is None:
        return {"error": "invalid function_address"}
    
    proto_text = prototype.strip()
    
    try:
        f = ida_funcs.get_func(parsed["value"])
    except Exception:
        f = None
    if not f:
        return {"error": "function not found"}
    
    start_ea = int(f.start_ea)
    
    # 获取旧类型
    old_decl = None
    try:
        old_t = ida_typeinf.tinfo_t()
        if idaapi.get_tinfo(old_t, start_ea):
            try:
                old_decl = ida_typeinf.print_tinfo('', 0, 0, ida_typeinf.PRTYPE_1LINE, old_t, '', '')  # type: ignore
            except Exception:
                old_decl = None
    except Exception:
        pass
    
    # 解析新类型
    tinfo = ida_typeinf.tinfo_t()
    parsed_name = None
    parse_ok = False
    parse_errors: List[str] = []
    
    variants = [
        ("idaapi.parse_decl", lambda: idaapi.parse_decl(tinfo, _get_idati(), proto_text, PT_SIL)),  # type: ignore
        ("ida_typeinf.parse_decl", lambda: ida_typeinf.parse_decl(tinfo, _get_idati(), proto_text, PT_SIL)),  # type: ignore
    ]
    
    for label, fn in variants:
        try:
            name = fn()
            if isinstance(name, (list, tuple)) and name:
                name = name[0]
            if isinstance(name, str) and name:
                parsed_name = name
            if tinfo and tinfo.is_func():
                parse_ok = True
                break
        except Exception as e:
            parse_errors.append(f"{label}: {e}")
    
    if not parse_ok or not tinfo or not tinfo.is_func():
        return {"error": "parse failed or not a function type", "details": parse_errors[:2]}
    
    # 应用类型
    try:
        applied = idaapi.apply_tinfo(start_ea, tinfo, idaapi.TINFO_DEFINITE)
    except Exception:
        try:
            applied = idaapi.apply_tinfo2(start_ea, tinfo, idaapi.TINFO_DEFINITE)  # type: ignore
        except Exception as e:
            return {"error": f"apply failed: {e}"}
    
    # 获取新类型
    new_decl = None
    try:
        nt = ida_typeinf.tinfo_t()
        if idaapi.get_tinfo(nt, start_ea):
            try:
                new_decl = ida_typeinf.print_tinfo('', 0, 0, ida_typeinf.PRTYPE_1LINE, nt, '', '')  # type: ignore
            except Exception:
                new_decl = None
    except Exception:
        pass
    
    return {
        "start_ea": hex_addr(start_ea),
        "applied": bool(applied),
        "old_type": old_decl,
        "new_type": new_decl,
        "parsed_name": parsed_name,
    }


# ============================================================================
# 局部变量类型
# ============================================================================

@tool
@idawrite
def set_local_variable_type(
    function_address: Annotated[Union[int, str], "Function start or internal address (hex or decimal)"],
    variable_name: Annotated[str, "Local variable name (exact match)"],
    new_type: Annotated[str, "C type fragment (e.g. int, char *, MyStruct *)"],
) -> dict:
    """Set local variable type (Hex-Rays)."""
    if function_address is None:
        return {"error": "invalid function_address"}
    if not variable_name:
        return {"error": "empty variable_name"}
    if not new_type or not new_type.strip():
        return {"error": "empty new_type"}
    
    parsed = parse_address(str(function_address))
    if not parsed["ok"] or parsed["value"] is None:
        return {"error": "invalid function_address"}
    
    type_text = new_type.strip()
    
    # 初始化 Hex-Rays
    try:
        if not ida_hexrays.init_hexrays_plugin():
            return {"error": "failed to init hex-rays"}
    except Exception:
        return {"error": "failed to init hex-rays"}
    
    # 定位函数
    try:
        f = ida_funcs.get_func(parsed["value"])
    except Exception:
        f = None
    if not f:
        return {"error": "function not found"}
    
    try:
        cfunc = ida_hexrays.decompile(f.start_ea)
    except Exception as e:
        return {"error": f"decompile failed: {e}"}
    if not cfunc:
        return {"error": "decompile returned None"}
    
    # 查找局部变量
    target = None
    try:
        for lv in cfunc.lvars:  # type: ignore
            try:
                if lv.name == variable_name:
                    target = lv
                    break
            except Exception:
                continue
    except Exception:
        return {"error": "iterate lvars failed"}
    
    if not target:
        return {"error": "local variable not found"}
    
    # 获取原类型
    old_type_str = None
    try:
        old_t = target.type()
        if old_t:
            try:
                old_type_str = ida_typeinf.print_tinfo('', 0, 0, ida_typeinf.PRTYPE_1LINE, old_t, '', '')  # type: ignore
            except Exception:
                old_type_str = None
    except Exception:
        pass
    
    # 解析新类型
    tinfo = ida_typeinf.tinfo_t()
    parse_ok = False
    errors: List[str] = []
    candidate_decl = f"{type_text} tmp;"
    
    variants = [
        ("idaapi.parse_decl", lambda: idaapi.parse_decl(tinfo, _get_idati(), candidate_decl, PT_SIL)),  # type: ignore
        ("ida_typeinf.parse_decl", lambda: ida_typeinf.parse_decl(tinfo, _get_idati(), candidate_decl, PT_SIL)),  # type: ignore
    ]
    
    for label, fn in variants:
        try:
            _ = fn()
            if tinfo and not tinfo.empty():
                parse_ok = True
                break
        except Exception as e:
            errors.append(f"{label}: {e}")
    
    if not parse_ok:
        return {"error": "parse type failed", "details": errors[:2]}
    
    # 应用
    try:
        applied = ida_hexrays.set_lvar_type(cfunc, target, tinfo)  # type: ignore
    except Exception as e:
        return {"error": f"set_lvar_type failed: {e}"}
    
    # 获取新类型
    new_type_str = None
    try:
        nt = target.type()
        if nt:
            try:
                new_type_str = ida_typeinf.print_tinfo('', 0, 0, ida_typeinf.PRTYPE_1LINE, nt, '', '')  # type: ignore
            except Exception:
                new_type_str = None
    except Exception:
        pass
    
    try:
        fname = idaapi.get_func_name(f.start_ea)
    except Exception:
        fname = "?"
    
    return {
        "function": fname,
        "start_ea": hex_addr(f.start_ea),
        "variable_name": variable_name,
        "old_type": old_type_str,
        "new_type": new_type_str,
        "applied": bool(applied),
    }


# ============================================================================
# 全局变量类型
# ============================================================================

@tool
@idawrite
def set_global_variable_type(
    variable_name: Annotated[str, "Global symbol name"],
    new_type: Annotated[str, "C type fragment"],
) -> dict:
    """Set global variable type."""
    if not variable_name:
        return {"error": "empty variable_name"}
    if not new_type or not new_type.strip():
        return {"error": "empty new_type"}
    
    type_text = new_type.strip()
    
    try:
        ea = idaapi.get_name_ea(idaapi.BADADDR, variable_name)
    except Exception:
        ea = idaapi.BADADDR
    
    if ea == idaapi.BADADDR:
        return {"error": "global not found"}
    
    # 拒绝函数起始
    try:
        f = ida_funcs.get_func(ea)
        if f and int(f.start_ea) == int(ea):
            return {"error": "target is function start"}
    except Exception:
        pass
    
    # 获取旧类型
    old_type_str = None
    try:
        ot = ida_typeinf.tinfo_t()
        if idaapi.get_tinfo(ot, ea):
            try:
                old_type_str = ida_typeinf.print_tinfo('', 0, 0, ida_typeinf.PRTYPE_1LINE, ot, '', '')  # type: ignore
            except Exception:
                old_type_str = None
    except Exception:
        pass
    
    # 解析新类型
    candidate = f"{type_text} __tmp_var;"
    tinfo = ida_typeinf.tinfo_t()
    parse_ok = False
    errors: List[str] = []
    
    variants = [
        ("idaapi.parse_decl", lambda: idaapi.parse_decl(tinfo, _get_idati(), candidate, PT_SIL)),  # type: ignore
        ("ida_typeinf.parse_decl", lambda: ida_typeinf.parse_decl(tinfo, _get_idati(), candidate, PT_SIL)),  # type: ignore
    ]
    
    for label, fn in variants:
        try:
            _ = fn()
            if tinfo and not tinfo.empty():
                parse_ok = True
                break
        except Exception as e:
            errors.append(f"{label}: {e}")
    
    if not parse_ok:
        return {"error": "parse type failed", "details": errors[:2]}
    
    # 应用
    try:
        applied = idaapi.apply_tinfo(ea, tinfo, idaapi.TINFO_DEFINITE)
    except Exception:
        try:
            applied = idaapi.apply_tinfo2(ea, tinfo, idaapi.TINFO_DEFINITE)  # type: ignore
        except Exception as e:
            return {"error": f"apply failed: {e}"}
    
    # 获取新类型
    new_type_str = None
    try:
        nt = ida_typeinf.tinfo_t()
        if idaapi.get_tinfo(nt, ea):
            try:
                new_type_str = ida_typeinf.print_tinfo('', 0, 0, ida_typeinf.PRTYPE_1LINE, nt, '', '')  # type: ignore
            except Exception:
                new_type_str = None
    except Exception:
        pass
    
    return {
        "ea": hex_addr(ea),
        "variable_name": variable_name,
        "old_type": old_type_str,
        "new_type": new_type_str,
        "applied": bool(applied),
    }


# ============================================================================
# 结构体列表
# ============================================================================

@tool
@idaread
def list_structs(
    pattern: Annotated[Optional[str], "Optional name filter"] = None,
) -> dict:
    """List all structures/unions defined in the database."""
    items: List[dict] = []
    
    try:
        # 使用 get_ordinal_limit() 获取 ordinal 上限（参考 ida-pro-mcp 实现）
        limit = ida_typeinf.get_ordinal_limit()  # type: ignore
        
        for ordinal in range(1, limit):
            try:
                tif = ida_typeinf.tinfo_t()
                # 使用 tinfo_t.get_numbered_type(None, ordinal) 方法
                tif.get_numbered_type(None, ordinal)
                
                # 只保留 UDT (User Defined Types: struct/union)
                if not tif.is_udt():
                    continue
                
                name = tif.get_type_name()
                if not name:
                    continue
                
                # 获取成员信息
                udt = ida_typeinf.udt_type_data_t()
                member_count = 0
                is_union = False
                if tif.get_udt_details(udt):
                    member_count = udt.size()
                    is_union = udt.is_union
                
                items.append({
                    "ordinal": ordinal,
                    "name": name,
                    "kind": "union" if is_union else "struct",
                    "size": tif.get_size(),
                    "members": member_count,
                })
            except Exception:
                continue
    except Exception:
        pass
    
    # 过滤
    if pattern:
        substr = pattern.lower()
        items = [it for it in items if substr in it.get('name', '').lower()]
    
    return {"total": len(items), "items": items}


# ============================================================================
# 结构体详情
# ============================================================================

@tool
@idaread
def get_struct_info(
    name: Annotated[str, "Structure/union name"],
) -> dict:
    """Get detailed structure/union definition with fields."""
    if not name or not name.strip():
        return {"error": "empty name"}
    
    name = name.strip()
    
    try:
        til = ida_typeinf.get_idati()
        tif = ida_typeinf.tinfo_t()
        
        # 尝试按名称获取类型
        if not tif.get_named_type(til, name):
            return {"error": "type not found", "name": name}
        
        if not (tif.is_struct() or tif.is_union()):
            return {"error": "not a struct/union", "name": name}
        
        kind = "struct" if tif.is_struct() else "union"
        size = tif.get_size()
        
        # 获取成员详情
        udt = ida_typeinf.udt_type_data_t()
        members: List[dict] = []
        
        if tif.get_udt_details(udt):
            for i in range(udt.size()):
                try:
                    member = udt[i]
                    mname = member.name if member.name else f"field_{i}"
                    mtype = member.type
                    moffset = member.offset // 8  # 位转字节
                    msize = member.size // 8 if member.size else None
                    
                    # 获取类型字符串
                    mtype_str = None
                    if mtype:
                        try:
                            mtype_str = ida_typeinf.print_tinfo('', 0, 0, ida_typeinf.PRTYPE_1LINE, mtype, '', '')
                        except Exception:
                            mtype_str = str(mtype)
                    
                    members.append({
                        "index": i,
                        "name": mname,
                        "type": mtype_str,
                        "offset": moffset,
                        "size": msize,
                    })
                except Exception:
                    continue
        
        return {
            "name": name,
            "kind": kind,
            "size": size if size != idaapi.BADADDR else None,
            "members": members,
            "member_count": len(members),
        }
    except Exception as e:
        return {"error": str(e), "name": name}
