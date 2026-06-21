#!/usr/bin/env python3
"""
IDA Pro 7.7+ MCP Server — ULTIMATE EDITION (FIXED)
Compatible: IDA 7.7+, Python 3.8+
Transport: HTTP on 127.0.0.1:18850
Features: 
  - Advanced Multi-Method String Search (ASCII/Unicode/Builtin)
  - Full Activity Logging to IDA Console
  - Advanced Instruction Dumping & Duplication Detection
  - Function Renaming & Advanced XREF Scanning
  - Complete Unfiltered Data Return
Usage: exec(__import__('urllib.request').request.urlopen('RAW_GITHUB_URL').read().decode())
"""

import json, threading, sys, traceback, time, io, math, hashlib
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
import socketserver
from collections import Counter, deque

# IDA 7.7+ Core APIs
import idaapi, idautils, idc
import ida_bytes, ida_segment, ida_name, ida_xref
import ida_funcs, ida_search, ida_auto, ida_nalt
import ida_ida, ida_typeinf, ida_kernwin, ida_struct
import ida_ua

# Hex-Rays Decompiler (optional)
_has_decompiler = False
try:
    import ida_hexrays
    _has_decompiler = ida_hexrays.init_hexrays_plugin()
except Exception:
    pass

# ===== GLOBAL LOGGER =====
def _log(msg):
    """Log message to IDA Output Window and Stderr"""
    timestamp = time.strftime("%H:%M:%S")
    formatted_msg = f"[MCP-SERVER] [{timestamp}] {msg}"
    try:
        idaapi.msg(formatted_msg + "\n")
    except:
        pass
    print(formatted_msg, file=sys.stderr)

# ===== IDA API COMPATIBILITY =====
def _get_inf():
    try: return idaapi.get_inf_structure()
    except: 
        try: import ida_ida; return ida_ida.inf
        except: return None

def _is_64bit():
    try: return bool(getattr(_get_inf(), 'is_64bit', False))
    except: return False

def _get_ptr_size(): return 8 if _is_64bit() else 4
PTR_SIZE = _get_ptr_size()
PORT, HOST = 18850, "127.0.0.1"

# ===== THREADING & EXECUTION HELPERS =====
def _resolve_address(address):
    if isinstance(address, int): return address
    if not address: return idaapi.BADADDR
    addr_str = str(address).strip()
    # Use idc for better script compatibility
    ea = idc.get_name_ea_simple(addr_str)
    if ea != idaapi.BADADDR: return ea
    try: return int(addr_str.replace("0x","").replace("0X",""), 16)
    except: 
        try: return int(addr_str)
        except: return idaapi.BADADDR

def _run_on_main(func, *args, mode=idaapi.MFF_READ, **kwargs):
    result = {"val": None, "err": None}
    def _wrap():
        try: 
            _log(f"Executing: {func.__name__}")
            result["val"] = func(*args, **kwargs)
            _log(f"Completed: {func.__name__}")
        except Exception as e:
            err_msg = f"{type(e).__name__}: {e}\n{traceback.format_exc()}"
            result["err"] = err_msg
            _log(f"ERROR in {func.__name__}: {err_msg}")
    if idaapi.is_main_thread(): _wrap()
    else: idaapi.execute_sync(_wrap, mode)
    if result["err"]: return {"_error": result["err"], "_partial": True}
    return result["val"] if result["val"] is not None else {}

def _safe_read(fn, *a, **kw): return _run_on_main(fn, *a, mode=idaapi.MFF_READ, **kw)
def _safe_write(fn, *a, **kw): return _run_on_main(fn, *a, mode=idaapi.MFF_WRITE, **kw)

def _get_disasm(ea):
    try:
        if not ida_bytes.is_code(idaapi.get_flags(ea)):
            return ""
        line = idaapi.generate_disasm_line(ea, idaapi.GENDSM_FORCE_CODE)
        return idaapi.tag_remove(line) if line else ""
    except: 
        try: return idc.GetDisasm(ea)
        except: return ""

def _get_bytes(ea, size):
    try: return ida_bytes.get_bytes(ea, size) or b""
    except: return b""

def _hex_bytes(b): return " ".join(f"{x:02X}" for x in b) if b else ""

def _entropy(data):
    if not data: return 0.0
    c = Counter(data)
    l = len(data)
    return -sum((v/l) * math.log2(v/l) for v in c.values())

# ===== CORE TOOLS =====
def preflight():
    def _impl():
        _log("Running preflight check...")
        data = {
            "_source": "preflight", "_timestamp": time.time(),
            "ida_version": idaapi.get_kernel_version(),
            "filename": idaapi.get_root_filename(),
            "input_path": idc.get_input_file_path(),
            "idb_path": idc.get_idb_path(),
            "auto_ok": idaapi.auto_is_ok(),
            "auto_qty": idaapi.get_auto_qty() if hasattr(idaapi, 'get_auto_qty') else None,
            "decompiler_available": _has_decompiler,
            "processor": getattr(_get_inf(), 'procname', 'unknown') if _get_inf() else 'unknown',
            "is_64bit": _is_64bit(), "ptr_size": PTR_SIZE,
            "imagebase": hex(getattr(_get_inf(), 'imagebase', 0)) if _get_inf() else None,
        }
        for name, getter in [
            ("function_count", lambda: len(list(idautils.Functions()))),
            ("segment_count", lambda: len(list(idautils.Segments()))),
            ("string_count", lambda: len(list(idautils.Strings()))),
            ("import_module_count", lambda: idaapi.get_import_module_qty()),
            ("export_count", lambda: len(list(idautils.Entries()))),
            ("struct_count", lambda: sum(1 for _ in idautils.Structs())),
        ]:
            try: data[name] = getter()
            except: data[name] = None
        return data
    return _safe_read(_impl)

def decompile(address):
    def _impl():
        _log(f"Decompiling address: {address}")
        data = {"_source": "decompile", "_address_input": address}
        if not _has_decompiler:
            data["_decompiler_status"] = "not_available"
            return data
        ea = _resolve_address(address)
        data["_address_resolved"] = hex(ea) if ea != idaapi.BADADDR else None
        if ea == idaapi.BADADDR:
            data["_error"] = "address_unresolved"
            return data
        func = ida_funcs.get_func(ea)
        data["_function_found"] = bool(func)
        if not func:
            data["_error"] = "no_function_at_address"
            return data
        data["function"] = {
            "name": idc.get_func_name(func.start_ea),
            "start_ea": hex(func.start_ea), "end_ea": hex(func.end_ea),
            "size": func.end_ea - func.start_ea,
            "flags": func.flags if hasattr(func, 'flags') else None,
            "frame": hex(func.frame) if hasattr(func, 'frame') else None,
        }
        try:
            cfunc = ida_hexrays.decompile(func.start_ea)
            if cfunc:
                data["pseudocode"] = str(cfunc)
                data["pseudocode_lines"] = data["pseudocode"].count('\n') + 1
                if hasattr(cfunc, 'entry_ea'): data["cfunc_entry_ea"] = hex(cfunc.entry_ea)
                if hasattr(cfunc, 'iflags'): data["cfunc_iflags"] = cfunc.iflags
            else:
                data["_decompile_empty"] = True
        except Exception as de:
            data["_decompile_exception"] = f"{type(de).__name__}: {de}"
        return data
    return _safe_read(_impl)

# ==============================================================================
# >>> NEW: ADVANCED STRING SEARCH (MULTI-METHOD) <<<
# ==============================================================================

def advanced_string_search(min_len=4, search_ascii=True, search_unicode=True, search_cstrings=True):
    """
    Finds strings using multiple methods:
    1. IDA's built-in string table (fastest)
    2. Manual byte scanning for ASCII/Unicode patterns
    3. C-string termination detection
    """
    def _impl():
        _log(f"Starting advanced string search (min_len={min_len})...")
        results = []
        seen_addrs = set()

        # Method 1: IDA Built-in Strings
        if search_cstrings:
            _log("Scanning IDA string table...")
            for s in idautils.Strings():
                if s.length >= min_len and s.ea not in seen_addrs:
                    seen_addrs.add(s.ea)
                    results.append({
                        "addr": hex(s.ea),
                        "value": str(s),
                        "length": s.length,
                        "type": "ida_builtin",
                        "str_type": s.strtype, # Fixed: was s.type
                        "func": idc.get_func_name(s.ea) if ida_funcs.get_func(s.ea) else None
                    })

        # Method 2: Manual Byte Scanning (for hidden/unrecognized strings)
        if search_ascii or search_unicode:
            _log("Scanning binary segments for raw patterns...")
            for seg_ea in idautils.Segments():
                seg = ida_segment.getseg(seg_ea)
                if not seg: continue
                # Skip non-readable segments
                if not (seg.perm & ida_segment.SEGPERM_READ): continue
                
                curr_ea = seg.start_ea
                end_ea = seg.end_ea
                
                while curr_ea < end_ea:
                    # Check for ASCII
                    if search_ascii and curr_ea not in seen_addrs:
                        b = ida_bytes.get_byte(curr_ea)
                        if 32 <= b <= 126:
                            # Potential start of ASCII string
                            str_buf = bytearray()
                            scan_ea = curr_ea
                            while scan_ea < end_ea:
                                cb = ida_bytes.get_byte(scan_ea)
                                if 32 <= cb <= 126:
                                    str_buf.append(cb)
                                    scan_ea += 1
                                elif cb == 0: # Null terminator
                                    break
                                else:
                                    break
                            
                            if len(str_buf) >= min_len:
                                seen_addrs.add(curr_ea)
                                results.append({
                                    "addr": hex(curr_ea),
                                    "value": str_buf.decode('ascii', errors='ignore'),
                                    "length": len(str_buf),
                                    "type": "raw_ascii_scan",
                                    "func": idc.get_func_name(curr_ea) if ida_funcs.get_func(curr_ea) else None
                                })
                                curr_ea = scan_ea # Skip ahead
                                continue

                    # Check for Unicode (UTF-16 LE)
                    if search_unicode and curr_ea + 1 < end_ea and curr_ea not in seen_addrs:
                        w = ida_bytes.get_word(curr_ea)
                        if 32 <= (w & 0xFF) <= 126 and (w >> 8) == 0:
                            str_buf = bytearray()
                            scan_ea = curr_ea
                            valid_unicode = True
                            while scan_ea + 1 < end_ea:
                                cw = ida_bytes.get_word(scan_ea)
                                char_val = cw & 0xFF
                                null_high = (cw >> 8) == 0
                                
                                if 32 <= char_val <= 126 and null_high:
                                    str_buf.append(char_val)
                                    scan_ea += 2
                                elif cw == 0: # Null terminator
                                    break
                                else:
                                    valid_unicode = False
                                    break
                            
                            if valid_unicode and len(str_buf) >= min_len:
                                seen_addrs.add(curr_ea)
                                results.append({
                                    "addr": hex(curr_ea),
                                    "value": str_buf.decode('ascii', errors='ignore'),
                                    "length": len(str_buf),
                                    "type": "raw_unicode_scan",
                                    "func": idc.get_func_name(curr_ea) if ida_funcs.get_func(curr_ea) else None
                                })
                                curr_ea = scan_ea
                                continue
                    
                    curr_ea += 1
        
        _log(f"String search complete. Found {len(results)} strings.")
        return {"results": results, "count": len(results), "methods_used": ["ida_builtin", "raw_ascii", "raw_unicode"]}
    return _safe_read(_impl)

# ==============================================================================
# >>> NEW: ADVANCED INSTRUCTION DUMPING & DUPLICATION DETECTION <<<
# ==============================================================================

def dump_function_instructions(address, include_bytes=True, detect_duplicates=True):
    """
    Dumps all instructions in a function with detailed metadata.
    Optionally detects duplicate instruction sequences.
    """
    def _impl():
        _log(f"Dumping instructions for: {address}")
        ea = _resolve_address(address)
        if ea == idaapi.BADADDR: return {"_error": "invalid_address"}
        
        func = ida_funcs.get_func(ea)
        if not func: return {"_error": "not_a_function"}
        
        instructions = []
        insn_hashes = {} # For duplicate detection
        duplicates = []
        
        curr_ea = func.start_ea
        while curr_ea < func.end_ea:
            if not ida_bytes.is_code(idaapi.get_flags(curr_ea)): # Fixed: was idaapi.isCode
                curr_ea = idc.NextHead(curr_ea)
                continue
                
            disasm = _get_disasm(curr_ea)
            size = idc.get_item_size(curr_ea)
            bytes_raw = _get_bytes(curr_ea, size) if include_bytes else b""
            
            # Decode instruction for advanced details
            insn = ida_ua.insn_t()
            ida_ua.decode_insn(insn, curr_ea)
            
            # Create a hash of the mnemonic + operand types for duplicate detection
            if detect_duplicates:
                op_types = tuple([op.type for op in insn.ops if op.type != ida_ua.o_void])
                sig = f"{insn.itype}_{op_types}"
                sig_hash = hashlib.md5(sig.encode()).hexdigest()[:8]
                
                if sig_hash in insn_hashes:
                    duplicates.append({
                        "addr": hex(curr_ea),
                        "disasm": disasm,
                        "original_addr": insn_hashes[sig_hash],
                        "signature": sig
                    })
                else:
                    insn_hashes[sig_hash] = hex(curr_ea)

            instr_entry = {
                "addr": hex(curr_ea),
                "disasm": disasm,
                "mnemonic": ida_ua.print_insn_mnem(curr_ea),
                "size": size,
                "itype": insn.itype,
                "bytes": _hex_bytes(bytes_raw) if include_bytes else None,
                "operands": []
            }
            
            # Extract operand details
            for i, op in enumerate(insn.ops):
                if op.type == ida_ua.o_void: break
                instr_entry["operands"].append({
                    "index": i,
                    "type": op.type,
                    "text": ida_ua.print_operand(curr_ea, i),
                    "value": op.value if op.type == ida_ua.o_imm else None,
                    "addr": hex(op.addr) if op.type in (ida_ua.o_near, ida_ua.o_far, ida_ua.o_mem) else None
                })
                
            instructions.append(instr_entry)
            curr_ea = idc.NextHead(curr_ea)
            
        _log(f"Dumped {len(instructions)} instructions. Found {len(duplicates)} potential duplicates.")
        return {
            "function": idc.get_func_name(func.start_ea),
            "start": hex(func.start_ea),
            "end": hex(func.end_ea),
            "instructions": instructions,
            "instruction_count": len(instructions),
            "duplicates": duplicates,
            "duplicate_count": len(duplicates)
        }
    return _safe_read(_impl)

# ==============================================================================
# >>> FUNCTION RENAMING FEATURES <<<
# ==============================================================================

def rename_function(address, new_name):
    """Rename a function and optionally demangle/update references"""
    def _impl():
        _log(f"Renaming function at {address} to {new_name}")
        data = {"_source": "rename_function", "_address_input": address, "_new_name": new_name}
        ea = _resolve_address(address)
        data["_address_resolved"] = hex(ea) if ea != idaapi.BADADDR else None
        if ea == idaapi.BADADDR: return {**data, "_error": "address_unresolved"}
        
        func = ida_funcs.get_func(ea)
        if not func: return {**data, "_error": "no_function_at_address"}
        
        old_name = idc.get_func_name(ea)
        # SN_NOWARN | SN_CHECK
        success = idc.set_name(ea, new_name, idc.SN_NOWARN | idc.SN_CHECK)
        
        data["old_name"] = old_name
        data["new_name"] = new_name if success else None
        data["success"] = bool(success)
        
        if success:
            # Try to update local types if possible
            try:
                if _has_decompiler:
                    ida_hexrays.rename_func(ea, new_name)
            except: pass
            
        return data
    return _safe_write(_impl)

def rename_by_pattern(pattern, prefix="sub_", limit=100):
    """Batch rename functions matching a pattern (e.g., all 'sub_' functions)"""
    def _impl():
        _log(f"Batch renaming functions matching '{pattern}'...")
        data = {"_source": "rename_by_pattern", "_pattern": pattern, "_prefix": prefix, "_limit": limit}
        renamed = []
        count = 0
        for ea in idautils.Functions():
            if count >= limit: break
            name = idc.get_func_name(ea)
            if name and pattern in name:
                new_name = f"{prefix}{count:04d}"
                if idc.set_name(ea, new_name, idc.SN_NOWARN | idc.SN_CHECK):
                    renamed.append({"addr": hex(ea), "old": name, "new": new_name})
                    count += 1
        data["renamed"] = renamed
        data["count"] = len(renamed)
        return data
    return _safe_write(_impl)

def set_function_comment(address, comment, repeatable=False):
    """Set comment for a function"""
    def _impl():
        _log(f"Setting comment for function at {address}")
        data = {"_source": "set_function_comment", "_address_input": address, "_comment": comment}
        ea = _resolve_address(address)
        data["_address_resolved"] = hex(ea) if ea != idaapi.BADADDR else None
        if ea == idaapi.BADADDR: return {**data, "_error": "address_unresolved"}
        
        func = ida_funcs.get_func(ea)
        if not func: return {**data, "_error": "no_function_at_address"}
        
        # 0 = regular, 1 = repeatable
        cmt_type = 1 if repeatable else 0
        success = idc.set_func_cmt(ea, comment, cmt_type)
        data["success"] = bool(success)
        return data
    return _safe_write(_impl)

# ==============================================================================
# >>> ADVANCED XREF SCANNING <<<
# ==============================================================================

def advanced_xref_scan(address, scan_depth=1, include_data=True, include_code=True):
    """
    Advanced scanner that recursively follows xrefs and categorizes them.
    Returns a tree-like structure of references.
    """
    def _impl():
        _log(f"Advanced XREF scan starting at {address} (depth={scan_depth})")
        data = {"_source": "advanced_xref_scan", "_address_input": address, "_depth": scan_depth}
        ea = _resolve_address(address)
        data["_address_resolved"] = hex(ea) if ea != idaapi.BADADDR else None
        if ea == idaapi.BADADDR: return data
        
        visited = set()
        results = []
        
        def _scan_node(curr_ea, depth):
            if curr_ea in visited or depth > scan_depth: return
            visited.add(curr_ea)
            
            node_info = {
                "addr": hex(curr_ea),
                "name": idc.get_name(curr_ea) or idc.get_func_name(curr_ea),
                "depth": depth,
                "incoming": [],
                "outgoing": []
            }
            
            # Scan Incoming
            if include_code:
                for ref in idautils.CodeRefsTo(curr_ea, 1):
                    if ref not in visited:
                        insn = ida_ua.insn_t()
                        ida_ua.decode_insn(insn, ref)
                        node_info["incoming"].append({
                            "from": hex(ref),
                            "type": "code_flow" if ida_bytes.is_code(idaapi.get_flags(ref)) else "code_jump",
                            "mnemonic": ida_ua.print_insn_mnem(ref),
                            "disasm": _get_disasm(ref)
                        })
            
            if include_data:
                for ref in idautils.DataRefsTo(curr_ea):
                    if ref not in visited:
                        node_info["incoming"].append({
                            "from": hex(ref),
                            "type": "data_ref",
                            "disasm": _get_disasm(ref)
                        })

            # Scan Outgoing
            if include_code:
                for ref in idautils.CodeRefsFrom(curr_ea, 1):
                     if ref not in visited:
                        node_info["outgoing"].append({
                            "to": hex(ref),
                            "type": "code_flow",
                            "name": idc.get_name(ref) or idc.get_func_name(ref)
                        })
                        
            if include_data:
                for ref in idautils.DataRefsFrom(curr_ea):
                    if ref not in visited:
                        node_info["outgoing"].append({
                            "to": hex(ref),
                            "type": "data_ref",
                            "name": idc.get_name(ref)
                        })

            results.append(node_info)
            
            # Recurse into outgoing code refs if depth allows
            if depth < scan_depth:
                for ref in idautils.CodeRefsFrom(curr_ea, 1):
                    _scan_node(ref, depth + 1)

        _scan_node(ea, 0)
        
        data["scan_tree"] = results
        data["total_nodes"] = len(results)
        return data
    return _safe_read(_impl)

def find_xref_chains(target_address, max_chains=50):
    """Find complete call chains leading TO a specific target"""
    def _impl():
        _log(f"Finding xref chains for target: {target_address}")
        data = {"_source": "find_xref_chains", "_target": target_address}
        target_ea = _resolve_address(target_address)
        data["_target_resolved"] = hex(target_ea) if target_ea != idaapi.BADADDR else None
        if target_ea == idaapi.BADADDR: return data
        
        chains = []
        # Start from all immediate callers
        callers = list(idautils.CodeRefsTo(target_ea, 1))
        
        for caller_ea in callers[:max_chains]:
            chain = [hex(target_ea)]
            curr = caller_ea
            visited_in_chain = {target_ea, caller_ea}
            
            # Walk back up to 5 levels
            for _ in range(5):
                func = ida_funcs.get_func(curr)
                if not func: break
                
                # Find who calls this function
                parents = list(idautils.CodeRefsTo(func.start_ea, 1))
                if not parents: break
                
                # Pick the first parent that isn't in our chain
                next_parent = None
                for p in parents:
                    if p not in visited_in_chain:
                        next_parent = p
                        break
                
                if next_parent:
                    chain.append(hex(curr))
                    visited_in_chain.add(next_parent)
                    curr = next_parent
                else:
                    chain.append(hex(curr))
                    break
            
            chains.append({
                "root_caller": hex(caller_ea),
                "chain": list(reversed(chain)), # Reverse so it reads Caller -> ... -> Target
                "length": len(chain)
            })
            
        data["chains"] = chains
        data["count"] = len(chains)
        return data
    return _safe_read(_impl)

def analyze_operand_xrefs(address, operand_index=0):
    """Analyze xrefs specifically generated by a certain operand in an instruction"""
    def _impl():
        _log(f"Analyzing operand xrefs at {address}")
        data = {"_source": "analyze_operand_xrefs", "_address_input": address, "_operand_idx": operand_index}
        ea = _resolve_address(address)
        data["_address_resolved"] = hex(ea) if ea != idaapi.BADADDR else None
        if ea == idaapi.BADADDR: return data
        
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, ea) <= 0:
            return {**data, "_error": "decode_failed"}
        
        op = insn.ops[operand_index]
        data["operand_type"] = op.type
        data["operand_text"] = ida_ua.print_operand(ea, operand_index)
        
        xrefs = []
        # If it's an immediate or displacement, it might point to something
        if op.type in (ida_ua.o_imm, ida_ua.o_displ, ida_ua.o_near, ida_ua.o_far):
            val = op.value if op.type == ida_ua.o_imm else op.addr
            if val and idaapi.is_mapped(val): # Fixed: was idaapi.isMapped
                # Get all xrefs to this value
                for ref in idautils.XrefsTo(val, 0):
                    xrefs.append({
                        "from": hex(ref.frm),
                        "type": ida_xref.xref_type_name(ref.type),
                        "disasm": _get_disasm(ref.frm)
                    })
        
        data["value_referenced"] = hex(val) if 'val' in dir() else None
        data["xrefs_to_value"] = xrefs
        data["count"] = len(xrefs)
        return data
    return _safe_read(_impl)

# ===== EXISTING XREF TOOLS (Kept for compatibility) =====
def xrefs_to(address):
    def _impl():
        _log(f"Getting xrefs to {address}")
        data = {"_source": "xrefs_to", "_address_input": address}
        ea = _resolve_address(address)
        data["_address_resolved"] = hex(ea) if ea != idaapi.BADADDR else None
        if ea == idaapi.BADADDR: return data
        xrefs = []
        for ref in idautils.XrefsTo(ea, 0):
            xref_data = {
                "frm": hex(ref.frm), "to": hex(ref.to),
                "type": ref.type,
                "type_name": ida_xref.xref_type_name(ref.type) if hasattr(ida_xref, 'xref_type_name') else None,
                "user": bool(getattr(ref, 'user', False)),
                "is_code": ida_bytes.is_code(idaapi.get_flags(ref.frm)) if idaapi.is_mapped(ref.frm) else None, # Fixed
                "from_func": idc.get_func_name(ref.frm) if ida_funcs.get_func(ref.frm) else None,
                "from_disasm": _get_disasm(ref.frm),
                "from_bytes": _hex_bytes(_get_bytes(ref.frm, 16)),
            }
            try:
                insn = idaapi.insn_t()
                if idaapi.decode_insn(insn, ref.frm) > 0:
                    xref_data["from_mnemonic"] = idaapi.print_insn_mnem(ref.frm)
                    xref_data["from_itype"] = insn.itype
                    xref_data["from_size"] = insn.size
            except: pass
            xrefs.append(xref_data)
        data["xrefs"] = xrefs; data["count"] = len(xrefs); data["target"] = hex(ea)
        return data
    return _safe_read(_impl)

def xrefs_from(address):
    def _impl():
        _log(f"Getting xrefs from {address}")
        data = {"_source": "xrefs_from", "_address_input": address}
        ea = _resolve_address(address)
        data["_address_resolved"] = hex(ea) if ea != idaapi.BADADDR else None
        if ea == idaapi.BADADDR: return data
        xrefs = []
        for ref in idautils.XrefsFrom(ea, 0):
            xrefs.append({
                "frm": hex(ref.frm), "to": hex(ref.to), "type": ref.type,
                "type_name": ida_xref.xref_type_name(ref.type) if hasattr(ida_xref, 'xref_type_name') else None,
                "user": bool(getattr(ref, 'user', False)),
                "to_name": idc.get_name(ref.to), "to_func": idc.get_func_name(ref.to) if ida_funcs.get_func(ref.to) else None,
                "to_mapped": idaapi.is_mapped(ref.to), # Fixed
                "to_disasm": _get_disasm(ref.to) if idaapi.is_mapped(ref.to) else None,
            })
        data["xrefs"] = xrefs; data["count"] = len(xrefs); data["source"] = hex(ea)
        return data
    return _safe_read(_impl)

def data_refs(address): return xrefs_to(address)
def code_refs(address): return xrefs_to(address)

def xref_statistics(address):
    def _impl():
        data = {"_source": "xref_statistics", "_address_input": address}
        ea = _resolve_address(address)
        data["_address_resolved"] = hex(ea) if ea != idaapi.BADADDR else None
        if ea == idaapi.BADADDR: return data
        stats = {"to": Counter(), "from": Counter()}
        to_details, from_details = [], []
        for ref in idautils.XrefsTo(ea, 0):
            tname = ida_xref.xref_type_name(ref.type) if hasattr(ida_xref, 'xref_type_name') else str(ref.type)
            stats["to"][tname] += 1; to_details.append({"frm": hex(ref.frm), "type": ref.type, "type_name": tname})
        for ref in idautils.XrefsFrom(ea, 0):
            tname = ida_xref.xref_type_name(ref.type) if hasattr(ida_xref, 'xref_type_name') else str(ref.type)
            stats["from"][tname] += 1; from_details.append({"to": hex(ref.to), "type": ref.type, "type_name": tname})
        data["statistics"] = {"to": dict(stats["to"]), "from": dict(stats["from"]), "to_total": sum(stats["to"].values()), "from_total": sum(stats["from"].values())}
        data["details"] = {"to": to_details, "from": from_details}
        return data
    return _safe_read(_impl)

def xrefs_by_type(address, xref_type="fl_CN"):
    def _impl():
        data = {"_source": "xrefs_by_type", "_address_input": address, "_filter_type": xref_type}
        ea = _resolve_address(address)
        data["_address_resolved"] = hex(ea) if ea != idaapi.BADADDR else None
        if ea == idaapi.BADADDR: return data
        target_type = getattr(idaapi, xref_type, None)
        if target_type is None:
            try: target_type = int(xref_type)
            except: data["_type_parse_error"] = f"Could not resolve xref_type: {xref_type}"; target_type = None
        xrefs = []
        for ref in idautils.XrefsTo(ea, 0):
            if target_type is None or ref.type == target_type:
                xrefs.append({
                    "frm": hex(ref.frm), "to": hex(ref.to), "type": ref.type,
                    "type_name": ida_xref.xref_type_name(ref.type) if hasattr(ida_xref, 'xref_type_name') else None,
                    "func": idc.get_func_name(ref.frm), "disasm": _get_disasm(ref.frm),
                    "bytes": _hex_bytes(_get_bytes(ref.frm, 32)),
                })
        data["xrefs"] = xrefs; data["count"] = len(xrefs)
        return data
    return _safe_read(_impl)

def xref_context(address, context_lines=3):
    def _impl():
        data = {"_source": "xref_context", "_address_input": address, "_context_lines": context_lines}
        ea = _resolve_address(address)
        data["_address_resolved"] = hex(ea) if ea != idaapi.BADADDR else None
        if ea == idaapi.BADADDR: return data
        results = []
        for ref in idautils.XrefsTo(ea, 0):
            ctx = []
            cur = max(0, ref.frm - context_lines * 16)
            end = ref.frm + context_lines * 16
            while cur < end and idaapi.is_mapped(cur): # Fixed
                ctx.append({"addr": hex(cur), "asm": _get_disasm(cur), "bytes": _hex_bytes(_get_bytes(cur, 16)), "is_code": ida_bytes.is_code(idaapi.get_flags(cur)), "is_target": cur == ref.frm})
                cur = idc.NextHead(cur)
                if cur == idaapi.BADADDR: break
            results.append({"xref_from": hex(ref.frm), "xref_type": ida_xref.xref_type_name(ref.type) if hasattr(ida_xref, 'xref_type_name') else ref.type, "xref_user": bool(getattr(ref, 'user', False)), "context": ctx})
        data["xref_contexts"] = results; data["count"] = len(results); data["target"] = hex(ea)
        return data
    return _safe_read(_impl)

def function_xrefs(address):
    def _impl():
        data = {"_source": "function_xrefs", "_address_input": address}
        ea = _resolve_address(address)
        data["_address_resolved"] = hex(ea) if ea != idaapi.BADADDR else None
        if ea == idaapi.BADADDR: return data
        func = ida_funcs.get_func(ea)
        data["_function_found"] = bool(func)
        if not func: return data
        data["function"] = {"name": idc.get_func_name(func.start_ea), "start_ea": hex(func.start_ea), "end_ea": hex(func.end_ea), "size": func.end_ea - func.start_ea}
        callers, callees = [], []
        for ref in idautils.XrefsTo(func.start_ea, 0):
            if ref.type in (idaapi.fl_CN, idaapi.fl_CF):
                caller_f = ida_funcs.get_func(ref.frm)
                callers.append({"addr": hex(ref.frm), "func_name": idc.get_func_name(ref.frm) if caller_f else None, "type": ida_xref.xref_type_name(ref.type) if hasattr(ida_xref, 'xref_type_name') else ref.type, "disasm": _get_disasm(ref.frm)})
        cur = func.start_ea
        while cur < func.end_ea:
            insn = idaapi.insn_t()
            if idaapi.decode_insn(insn, cur) > 0 and insn.itype == idaapi.NN_call:
                ta = insn.Op1.addr
                if ta and idaapi.is_mapped(ta): # Fixed
                    callee_f = ida_funcs.get_func(ta)
                    callees.append({"addr": hex(ta), "func_name": idc.get_func_name(ta) if callee_f else None, "call_site": hex(cur), "call_disasm": _get_disasm(cur)})
            cur = idc.NextHead(cur)
            if cur == idaapi.BADADDR: break
        data["callers"] = callers; data["callees"] = callees; data["caller_count"] = len(callers); data["callee_count"] = len(callees)
        return data
    return _safe_read(_impl)

def call_graph(address, depth=2):
    def _impl():
        data = {"_source": "call_graph", "_address_input": address, "_depth": depth}
        ea = _resolve_address(address)
        data["_address_resolved"] = hex(ea) if ea != idaapi.BADADDR else None
        if ea == idaapi.BADADDR: return data
        result = {"target": hex(ea), "name": idc.get_func_name(ea), "callers": [], "callees": []}
        seen_callers, seen_callees = set(), set()
        def _collect_callers(tgt, d, cd=0):
            if cd >= d: return []
            out = []
            for ref in idautils.XrefsTo(tgt, 0):
                if ref.type in (idaapi.fl_CN, idaapi.fl_CF):
                    f = ida_funcs.get_func(ref.frm)
                    if f and f.start_ea not in seen_callers:
                        seen_callers.add(f.start_ea)
                        entry = {"addr": hex(ref.frm), "name": idc.get_func_name(f.start_ea), "depth": cd+1, "type": ida_xref.xref_type_name(ref.type) if hasattr(ida_xref, 'xref_type_name') else ref.type}
                        if cd+1 < d: entry["callers"] = _collect_callers(f.start_ea, d, cd+1)
                        out.append(entry)
            return out
        def _collect_callees(tgt, d, cd=0):
            if cd >= d: return []
            out = []
            f = ida_funcs.get_func(tgt)
            if not f: return out
            cur = f.start_ea
            while cur < f.end_ea:
                insn = idaapi.insn_t()
                if idaapi.decode_insn(insn, cur) > 0 and insn.itype == idaapi.NN_call:
                    ta = insn.Op1.addr
                    if ta and idaapi.is_mapped(ta): # Fixed
                        tf = ida_funcs.get_func(ta)
                        if tf and tf.start_ea not in seen_callees:
                            seen_callees.add(tf.start_ea)
                            entry = {"addr": hex(ta), "name": idc.get_func_name(tf.start_ea), "depth": cd+1, "call_site": hex(cur)}
                            if cd+1 < d: entry["callees"] = _collect_callees(ta, d, cd+1)
                            out.append(entry)
                cur = idc.NextHead(cur)
                if cur == idaapi.BADADDR: break
            return out
        result["callers"] = _collect_callers(ea, depth)
        result["callees"] = _collect_callees(ea, depth)
        data["graph"] = result; data["stats"] = {"unique_callers": len(seen_callers), "unique_callees": len(seen_callees)}
        return data
    return _safe_read(_impl)

def xref_graph(address, depth=2): return call_graph(address, depth)

def find_orphan_functions(min_xrefs=0):
    def _impl():
        data = {"_source": "find_orphan_functions", "_min_xrefs": min_xrefs}
        orphans = []
        for ea in idautils.Functions():
            func = ida_funcs.get_func(ea)
            if not func: continue
            xref_count = sum(1 for _ in idautils.XrefsTo(func.start_ea, 0))
            if xref_count <= min_xrefs:
                orphans.append({"addr": hex(ea), "name": idc.get_func_name(ea), "size": func.end_ea - func.start_ea, "incoming_xrefs": xref_count, "disasm_preview": _get_disasm(ea)})
        data["orphans"] = orphans; data["count"] = len(orphans); data["total_functions"] = len(list(idautils.Functions()))
        return data
    return _safe_read(_impl)

def find_hot_functions(min_callers=10):
    def _impl():
        data = {"_source": "find_hot_functions", "_min_callers": min_callers}
        hot = []
        for ea in idautils.Functions():
            func = ida_funcs.get_func(ea)
            if not func: continue
            callers = [r for r in idautils.XrefsTo(func.start_ea, 0) if r.type in (idaapi.fl_CN, idaapi.fl_CF)]
            if len(callers) >= min_callers:
                hot.append({"addr": hex(ea), "name": idc.get_func_name(ea), "caller_count": len(callers), "callers": [{"from": hex(r.frm), "func": idc.get_func_name(r.frm)} for r in callers], "size": func.end_ea - func.start_ea})
        hot.sort(key=lambda x: x["caller_count"], reverse=True)
        data["hot_functions"] = hot; data["count"] = len(hot); data["total_functions"] = len(list(idautils.Functions()))
        return data
    return _safe_read(_impl)

def find_xref_path(start_addr, end_addr, max_depth=10):
    def _impl():
        data = {"_source": "find_xref_path", "_start": start_addr, "_end": end_addr, "_max_depth": max_depth}
        start_ea, end_ea = _resolve_address(start_addr), _resolve_address(end_addr)
        data["_start_resolved"] = hex(start_ea) if start_ea != idaapi.BADADDR else None
        data["_end_resolved"] = hex(end_ea) if end_ea != idaapi.BADADDR else None
        if start_ea == idaapi.BADADDR or end_ea == idaapi.BADADDR: return data
        queue = deque([(start_ea, [start_ea])])
        visited = {start_ea}
        path_found = None; nodes_searched = 0
        while queue:
            curr, path = queue.popleft(); nodes_searched += 1
            if curr == end_ea: path_found = path; break
            if len(path) >= max_depth: continue
            for ref in idautils.XrefsFrom(curr, 0):
                if ref.to not in visited and idaapi.is_mapped(ref.to): # Fixed
                    visited.add(ref.to); queue.append((ref.to, path + [ref.to]))
        data["found"] = path_found is not None
        if path_found: data["path"] = [hex(a) for a in path_found]; data["length"] = len(path_found)
        data["searched_nodes"] = nodes_searched; data["visited_count"] = len(visited)
        return data
    return _safe_read(_impl)

def list_function_xrefs(func_address, include_disasm=True):
    def _impl():
        data = {"_source": "list_function_xrefs", "_func_address": func_address, "_include_disasm": include_disasm}
        ea = _resolve_address(func_address)
        data["_address_resolved"] = hex(ea) if ea != idaapi.BADADDR else None
        if ea == idaapi.BADADDR: return data
        func = ida_funcs.get_func(ea)
        data["_function_found"] = bool(func)
        if not func: return data
        data["function"] = {"name": idc.get_func_name(func.start_ea), "start_ea": hex(func.start_ea), "end_ea": hex(func.end_ea), "size": func.end_ea - func.start_ea}
        xrefs = []
        cur = func.start_ea
        while cur < func.end_ea:
            for ref in idautils.XrefsFrom(cur, 0):
                entry = {"at": hex(cur), "to": hex(ref.to), "type": ref.type, "type_name": ida_xref.xref_type_name(ref.type) if hasattr(ida_xref, 'xref_type_name') else None, "target_name": idc.get_name(ref.to), "target_func": idc.get_func_name(ref.to) if ida_funcs.get_func(ref.to) else None}
                if include_disasm: entry["disasm"] = _get_disasm(cur); entry["bytes"] = _hex_bytes(_get_bytes(cur, 16))
                xrefs.append(entry)
            cur = idc.NextHead(cur)
            if cur == idaapi.BADADDR: break
        data["xrefs"] = xrefs; data["count"] = len(xrefs)
        return data
    return _safe_read(_impl)

def debug_info():
    def _impl():
        data = {"_source": "debug_info", "_timestamp": time.time()}
        try: data["ida_loaded"] = bool(idaapi.get_root_filename())
        except: data["ida_loaded"] = False
        try: data["filename"] = idaapi.get_root_filename()
        except: data["filename"] = None
        try: data["input_path"] = idc.get_input_file_path()
        except: data["input_path"] = None
        try: data["auto_ok"] = idaapi.auto_is_ok()
        except: data["auto_ok"] = None
        try: data["auto_qty"] = idaapi.get_auto_qty()
        except: data["auto_qty"] = None
        data["decompiler"] = _has_decompiler; data["ptr_size"] = PTR_SIZE; data["is_64bit"] = _is_64bit()
        inf = _get_inf()
        if inf:
            try: data["imagebase"] = hex(getattr(inf, 'imagebase', 0))
            except: pass
            try: data["procname"] = getattr(inf, 'procname', None) # Fixed: was procName
            except: pass
        for name, getter in [
            ("functions", lambda: list(idautils.Functions())),
            ("segments", lambda: list(idautils.Segments())),
            ("strings", lambda: list(idautils.Strings())),
            ("imports", lambda: [idaapi.get_import_module_name(i) for i in range(idaapi.get_import_module_qty())]),
            ("exports", lambda: list(idautils.Entries())),
            ("structs", lambda: list(idautils.Structs())),
        ]:
            try: items = getter(); data[f"{name}_count"] = len(items); data[f"{name}_sample"] = [str(x) for x in items[:10]]
            except Exception as e: data[f"{name}_error"] = str(e)
        return data
    return _safe_read(_impl)

def get_disasm_full(address, count=100):
    ea = _resolve_address(address)
    def _impl():
        data = {"_source": "get_disasm_full", "_address_input": address, "_count_requested": count}
        data["_address_resolved"] = hex(ea) if ea != idaapi.BADADDR else None
        if ea == idaapi.BADADDR or not idaapi.is_mapped(ea): return data # Fixed
        out = []
        cur = ea
        for i in range(count):
            if not idaapi.is_mapped(cur) or not ida_bytes.is_code(idaapi.get_flags(cur)): break # Fixed
            out.append({"addr": hex(cur), "asm": _get_disasm(cur), "bytes": _hex_bytes(_get_bytes(cur, 32)), "flags": idaapi.get_flags(cur), "is_code": ida_bytes.is_code(idaapi.get_flags(cur)), "is_data": ida_bytes.is_data(idaapi.get_flags(cur)), "func": idc.get_func_name(cur) if ida_funcs.get_func(cur) else None})
            cur = idc.NextHead(cur)
            if cur == idaapi.BADADDR: break
        data["instructions"] = out; data["count_returned"] = len(out)
        return data
    return _safe_read(_impl)

def list_functions_full(limit=None):
    def _impl():
        data = {"_source": "list_functions_full", "_limit": limit}
        funcs = []; total = 0
        for ea in idautils.Functions():
            total += 1
            if limit and len(funcs) >= limit: data["_truncated"] = True; break
            f = ida_funcs.get_func(ea)
            if not f: continue
            funcs.append({"addr": hex(ea), "name": idc.get_func_name(ea), "start_ea": hex(f.start_ea), "end_ea": hex(f.end_ea), "size": f.end_ea - f.start_ea, "flags": f.flags if hasattr(f, 'flags') else None, "frame": hex(f.frame) if hasattr(f, 'frame') else None, "owner": f.owner if hasattr(f, 'owner') else None, "xref_count_to": sum(1 for _ in idautils.XrefsTo(f.start_ea, 0)), "first_insn": _get_disasm(f.start_ea)})
        data["functions"] = funcs; data["count_returned"] = len(funcs); data["total_in_database"] = total
        return data
    return _safe_read(_impl)

def search_full(pattern, search_type="bytes"):
    def _impl():
        data = {"_source": "search_full", "_pattern": pattern, "_type": search_type}
        results = []
        if search_type == "bytes":
            pat = pattern.replace(" ", "").replace("??", "\\x00")
            ea = ida_search.find_binary(0, idaapi.BADADDR, pat, 16, ida_search.SEARCH_DOWN)
            while ea != idaapi.BADADDR:
                results.append({"addr": hex(ea), "bytes": _hex_bytes(_get_bytes(ea, 64)), "disasm": _get_disasm(ea), "segment": ida_segment.get_segm_name(ida_segment.getseg(ea)) if ida_segment.getseg(ea) else None})
                ea = ida_search.find_binary(ea+1, idaapi.BADADDR, pat, 16, ida_search.SEARCH_DOWN)
        elif search_type == "text":
            for ea in idautils.Heads():
                if pattern.lower() in _get_disasm(ea).lower():
                    results.append({"addr": hex(ea), "disasm": _get_disasm(ea), "bytes": _hex_bytes(_get_bytes(ea, 32)), "func": idc.get_func_name(ea) if ida_funcs.get_func(ea) else None})
        elif search_type == "string":
            for s in idautils.Strings():
                if pattern.lower() in str(s).lower():
                    results.append({"addr": hex(s.ea), "string": str(s), "length": s.length, "type": s.strtype, "func": idc.get_func_name(s.ea) if ida_funcs.get_func(s.ea) else None}) # Fixed: s.type -> s.strtype
        data["results"] = results; data["count"] = len(results)
        return data
    return _safe_read(_impl)

# ===== TOOL REGISTRY =====
TOOL_MAP = {
    "ida_preflight": {"fn": lambda a: preflight(), "schema": {"type": "object", "properties": {}, "required": []}},
    "ida_decompile": {"fn": lambda a: decompile(a.get("address")), "schema": {"type": "object", "properties": {"address": {"type": "string"}}, "required": []}},
    
    # --- NEW ADVANCED FEATURES ---
    "ida_advanced_string_search": {"fn": lambda a: advanced_string_search(a.get("min_len", 4), a.get("search_ascii", True), a.get("search_unicode", True), a.get("search_cstrings", True)), "schema": {"type": "object", "properties": {"min_len": {"type": "integer"}, "search_ascii": {"type": "boolean"}, "search_unicode": {"type": "boolean"}, "search_cstrings": {"type": "boolean"}}, "required": []}},
    "ida_dump_function_instructions": {"fn": lambda a: dump_function_instructions(a.get("address"), a.get("include_bytes", True), a.get("detect_duplicates", True)), "schema": {"type": "object", "properties": {"address": {"type": "string"}, "include_bytes": {"type": "boolean"}, "detect_duplicates": {"type": "boolean"}}, "required": []}},
    
    # --- RENAME TOOLS ---
    "ida_rename_function": {"fn": lambda a: rename_function(a.get("address"), a.get("new_name")), "schema": {"type": "object", "properties": {"address": {"type": "string"}, "new_name": {"type": "string"}}, "required": []}},
    "ida_rename_by_pattern": {"fn": lambda a: rename_by_pattern(a.get("pattern"), a.get("prefix", "sub_"), a.get("limit", 100)), "schema": {"type": "object", "properties": {"pattern": {"type": "string"}, "prefix": {"type": "string"}, "limit": {"type": "integer"}}, "required": []}},
    "ida_set_function_comment": {"fn": lambda a: set_function_comment(a.get("address"), a.get("comment"), a.get("repeatable", False)), "schema": {"type": "object", "properties": {"address": {"type": "string"}, "comment": {"type": "string"}, "repeatable": {"type": "boolean"}}, "required": []}},

    # --- ADVANCED XREF TOOLS ---
    "ida_advanced_xref_scan": {"fn": lambda a: advanced_xref_scan(a.get("address"), a.get("scan_depth", 1), a.get("include_data", True), a.get("include_code", True)), "schema": {"type": "object", "properties": {"address": {"type": "string"}, "scan_depth": {"type": "integer"}, "include_data": {"type": "boolean"}, "include_code": {"type": "boolean"}}, "required": []}},
    "ida_find_xref_chains": {"fn": lambda a: find_xref_chains(a.get("target_address"), a.get("max_chains", 50)), "schema": {"type": "object", "properties": {"target_address": {"type": "string"}, "max_chains": {"type": "integer"}}, "required": []}},
    "ida_analyze_operand_xrefs": {"fn": lambda a: analyze_operand_xrefs(a.get("address"), a.get("operand_index", 0)), "schema": {"type": "object", "properties": {"address": {"type": "string"}, "operand_index": {"type": "integer"}}, "required": []}},

    # --- EXISTING TOOLS ---
    "ida_xrefs_to": {"fn": lambda a: xrefs_to(a.get("address")), "schema": {"type": "object", "properties": {"address": {"type": "string"}}, "required": []}},
    "ida_xrefs_from": {"fn": lambda a: xrefs_from(a.get("address")), "schema": {"type": "object", "properties": {"address": {"type": "string"}}, "required": []}},
    "ida_data_refs": {"fn": lambda a: data_refs(a.get("address")), "schema": {"type": "object", "properties": {"address": {"type": "string"}}, "required": []}},
    "ida_code_refs": {"fn": lambda a: code_refs(a.get("address")), "schema": {"type": "object", "properties": {"address": {"type": "string"}}, "required": []}},
    "ida_xref_statistics": {"fn": lambda a: xref_statistics(a.get("address")), "schema": {"type": "object", "properties": {"address": {"type": "string"}}, "required": []}},
    "ida_xrefs_by_type": {"fn": lambda a: xrefs_by_type(a.get("address"), a.get("xref_type", "fl_CN")), "schema": {"type": "object", "properties": {"address": {"type": "string"}, "xref_type": {"type": "string"}}, "required": []}},
    "ida_xref_context": {"fn": lambda a: xref_context(a.get("address"), a.get("context_lines", 3)), "schema": {"type": "object", "properties": {"address": {"type": "string"}, "context_lines": {"type": "integer"}}, "required": []}},
    "ida_function_xrefs": {"fn": lambda a: function_xrefs(a.get("address")), "schema": {"type": "object", "properties": {"address": {"type": "string"}}, "required": []}},
    "ida_call_graph": {"fn": lambda a: call_graph(a.get("address"), a.get("depth", 2)), "schema": {"type": "object", "properties": {"address": {"type": "string"}, "depth": {"type": "integer"}}, "required": []}},
    "ida_xref_graph": {"fn": lambda a: xref_graph(a.get("address"), a.get("depth", 2)), "schema": {"type": "object", "properties": {"address": {"type": "string"}, "depth": {"type": "integer"}}, "required": []}},
    "ida_find_orphan_functions": {"fn": lambda a: find_orphan_functions(a.get("min_xrefs", 0)), "schema": {"type": "object", "properties": {"min_xrefs": {"type": "integer"}}, "required": []}},
    "ida_find_hot_functions": {"fn": lambda a: find_hot_functions(a.get("min_callers", 10)), "schema": {"type": "object", "properties": {"min_callers": {"type": "integer"}}, "required": []}},
    "ida_find_xref_path": {"fn": lambda a: find_xref_path(a.get("start_addr"), a.get("end_addr"), a.get("max_depth", 10)), "schema": {"type": "object", "properties": {"start_addr": {"type": "string"}, "end_addr": {"type": "string"}, "max_depth": {"type": "integer"}}, "required": []}},
    "ida_list_function_xrefs": {"fn": lambda a: list_function_xrefs(a.get("func_address"), a.get("include_disasm", True)), "schema": {"type": "object", "properties": {"func_address": {"type": "string"}, "include_disasm": {"type": "boolean"}}, "required": []}},
    "ida_get_disasm_full": {"fn": lambda a: get_disasm_full(a.get("address"), a.get("count", 100)), "schema": {"type": "object", "properties": {"address": {"type": "string"}, "count": {"type": "integer"}}, "required": []}},
    "ida_list_functions_full": {"fn": lambda a: list_functions_full(a.get("limit")), "schema": {"type": "object", "properties": {"limit": {"type": "integer"}}, "required": []}},
    "ida_search_full": {"fn": lambda a: search_full(a.get("pattern", ""), a.get("search_type", "bytes")), "schema": {"type": "object", "properties": {"pattern": {"type": "string"}, "search_type": {"type": "string"}}, "required": []}},
    "ida_debug_info": {"fn": lambda a: debug_info(), "schema": {"type": "object", "properties": {}, "required": []}},
}

TOOLS = [{"name": name, "description": f"FULL-DATA tool: {name}", "inputSchema": cfg["schema"]} for name, cfg in TOOL_MAP.items()]

# ===== HTTP SERVER =====
class ThreadedHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, fmt, *args): 
        try: idaapi.msg(f"[HTTP] {args[0]}\n")
        except: print(f"[HTTP] {args[0]}", file=sys.stderr)
        
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        
    def _json(self, data, status=200):
        body = json.dumps(data, default=str, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self._cors(); self.end_headers(); self.wfile.write(body)
        
    def do_OPTIONS(self): 
        self.send_response(204); self._cors(); self.end_headers()
        
    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/mcp", "/", ""): 
            self._json({"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}, "serverInfo": {"name": "ida-ultimate-mcp", "version": "5.0"}})
        elif path == "/health": 
            self._json({"ok": True, "port": PORT, "ptr_size": PTR_SIZE, "tools": len(TOOLS), "decompiler": _has_decompiler, "mode": "full-data-return"})
        elif path == "/tools": 
            self._json({"tools": TOOLS})
        elif path == "/debug": 
            self._json(debug_info())
        else: 
            self._json({"error": "Not found"}, 404)
            
    def do_POST(self):
        if urlparse(self.path).path not in ("/mcp", "/", ""):
            self._json({"error": "Not found"}, 404); return
        try:
            length = int(self.headers.get("Content-Length", 0))
            req = json.loads(self.rfile.read(length).decode())
        except Exception as e:
            self._json({"_parse_error": str(e)}, 400); return
            
        req_id, method, params = req.get("id"), req.get("method"), req.get("params", {})
        try: idaapi.msg(f"[MCP] {method}\n")
        except: print(f"[MCP] {method}", file=sys.stderr)
        
        try:
            if method == "initialize":
                self._json({"jsonrpc": "2.0", "id": req_id, "result": {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}, "serverInfo": {"name": "ida-ultimate-mcp", "version": "5.0"}}})
            elif method == "tools/list":
                self._json({"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}})
            elif method == "tools/call":
                name, args = params.get("name"), params.get("arguments", {})
                if name not in TOOL_MAP: 
                    self._json({"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": json.dumps({"_error": f"Unknown tool: {name}", "_available_tools": list(TOOL_MAP.keys())}, default=str)}]}})
                    return
                result = TOOL_MAP[name]["fn"](args or {})
                if result is None: result = {"_note": "function_returned_none"}
                self._json({"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": json.dumps(result, default=str, ensure_ascii=False)}]}})
            elif method == "notifications/initialized":
                self.send_response(202); self._cors(); self.end_headers()
            else:
                self._json({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Method not found: {method}"}})
        except Exception as e:
            try: idaapi.msg(f"[ERR] {e}\n")
            except: print(f"[ERR] {e}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
            self._json({"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": json.dumps({"_exception": f"{type(e).__name__}: {e}", "_traceback": traceback.format_exc()}, default=str)}]}})

def run_server():
    srv = ThreadedHTTPServer((HOST, PORT), Handler)
    try: idaapi.msg(f"[✓] IDA Ultimate MCP v5.0 started on http://{HOST}:{PORT}/mcp\n")
    except: print(f"[✓] IDA Ultimate MCP v5.0 started on http://{HOST}:{PORT}/mcp", file=sys.stderr)
    try: idaapi.msg(f"[✓] Tools loaded: {len(TOOLS)} | Decompiler: {_has_decompiler}\n")
    except: print(f"[✓] Tools loaded: {len(TOOLS)} | Decompiler: {_has_decompiler}", file=sys.stderr)
    srv.serve_forever()

if __name__ == "__main__":
    t = threading.Thread(target=run_server, daemon=True)
    t.start()
    try: idaapi.msg(f"[✓] Server thread started on port {PORT}!\n")
    except: print(f"[✓] Server thread started on port {PORT}!", file=sys.stderr)
