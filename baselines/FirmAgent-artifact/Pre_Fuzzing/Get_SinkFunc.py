import json
from collections import deque
import ida_auto
import idaapi
import idautils
import idc
import os

ida_auto.auto_wait()

CI_SINKS = [
    "CsteSystem", "system", "_system", "doSystemCmd", "twsystem",
    "doSystem", "popen", "execv", "execve", "FCGI_popen", "rut_doSystemAction"
]
BOF_SINKS = ["strcpy", "strcat", "sprintf", "vsprintf", "gets", "sscanf", "cmsUtl_strcpy"]


def op_constant(op, expr=None):
    if op == idaapi.cot_obj and expr is not None:
        obj = expr.obj_ea
        seg = idaapi.getseg(obj)
        seg_name = idaapi.get_segm_name(seg) if seg else ""
        return seg_name in {'.rodata', '.rdata', 'LOAD'}
    if op == idaapi.cot_ref and expr is not None:
        return op_constant(expr.x.op, expr.x)
    return op in {idaapi.cot_num, idaapi.cot_fnum, idaapi.cot_str}


def arg_constant(cfunc, address):
    item = cfunc.body.find_closest_addr(address)
    if item is None or item.cexpr is None:
        return False
    expr = item.cexpr
    try:
        name = idc.get_func_name(expr.x.obj_ea)
        if name in CI_SINKS:
            if expr.op != idaapi.cot_call:
                return False
            for index in range(expr.a.size()):
                arg_expr = expr.a[index]
                cur = arg_expr.x if arg_expr.op == idaapi.cot_cast else arg_expr
                if not op_constant(cur.op, cur):
                    return True
            return False
        if name in ["strcpy", "cmsUtl_strcpy", "strcat"]:
            if expr.op != idaapi.cot_call or expr.a.size() < 2:
                return False
            arg_expr = expr.a[1]
            cur = arg_expr.x if arg_expr.op == idaapi.cot_cast else arg_expr
            return not op_constant(cur.op, cur)
        if name == "sscanf":
            if expr.op != idaapi.cot_call or expr.a.size() < 1:
                return False
            arg_expr = expr.a[0]
            cur = arg_expr.x if arg_expr.op == idaapi.cot_cast else arg_expr
            return not op_constant(cur.op, cur)
        if name == "sprintf":
            if expr.op != idaapi.cot_call:
                return False
            for index in range(2, expr.a.size()):
                arg_expr = expr.a[index]
                cur = arg_expr.x if arg_expr.op == idaapi.cot_cast else arg_expr
                if not op_constant(cur.op, cur):
                    return True
            return False
        return True
    except Exception as err:
        print(f"[!] arg_constant exception @ {hex(address)}: {err}")
        return False


def _find_block_for_ea(flowchart, ea):
    for block in flowchart:
        if block.start_ea <= ea < block.end_ea:
            return block
    return None


def _backward_reachable_blocks(func, sink_call_ea):
    flowchart = idaapi.FlowChart(func, flags=idaapi.FC_PREDS)
    sink_block = _find_block_for_ea(flowchart, sink_call_ea)
    if sink_block is None:
        return []
    queue = deque([sink_block])
    visited = {sink_block.id}
    blocks = []
    while queue:
        block = queue.popleft()
        blocks.append(block)
        for pred in block.preds():
            if pred.id not in visited:
                visited.add(pred.id)
                queue.append(pred)
    blocks.sort(key=lambda blk: blk.start_ea)
    return blocks


def _direct_caller_functions(func_start_ea):
    callers = set()
    for xref in idautils.CodeRefsTo(func_start_ea, 0):
        caller_func = idaapi.get_func(xref)
        if caller_func is not None:
            callers.add(caller_func.start_ea)
    return callers


def _backward_reachable_functions_with_graph(sink_caller_func_start):
    """
    BFS 向上追溯所有调用者，同时记录调用图（callee -> set of callers）。
    返回:
        visited: 所有可达函数地址集合
        call_graph: dict { callee_start -> set(caller_start) }，仅包含 visited 内的边
    """
    queue = deque([sink_caller_func_start])
    visited = {sink_caller_func_start}
    # callee -> callers（在 visited 范围内）
    call_graph = {}

    while queue:
        current = queue.popleft()
        callers = _direct_caller_functions(current)
        call_graph[current] = callers & visited  # 先只记录已知的，下面补全

        for pred_func in callers:
            if pred_func not in visited:
                visited.add(pred_func)
                queue.append(pred_func)

    # 补全 call_graph：重新建边（visited 内所有 callee -> caller）
    # called_by[func] = set of funcs in visited that call func
    called_by = {f: set() for f in visited}
    for func_start in visited:
        for caller in _direct_caller_functions(func_start):
            if caller in visited:
                called_by[func_start].add(caller)

    return visited, called_by


def _find_root_functions(visited, called_by):
    """
    在 visited 中找到没有任何 visited 内调用者的函数（即调用链顶端 / 入度为0的节点）。
    """
    roots = [f for f in visited if len(called_by.get(f, set())) == 0]
    return roots


def _backward_reachable_functions(sink_caller_func_start):
    """兼容旧接口，仅返回排序后的函数列表。"""
    visited, _ = _backward_reachable_functions_with_graph(sink_caller_func_start)
    return sorted(visited)


def _collect_sink_calls(sinks):
    sink_calls = []
    legacy_func_max_callsite = {}
    for sink_name in sinks:
        sink_ea = idc.get_name_ea_simple(sink_name)
        if sink_ea == idaapi.BADADDR:
            print(f"[-] Sink function '{sink_name}' not found in the binary.")
            continue
        for xref in idautils.CodeRefsTo(sink_ea, 0):
            func_start = idc.get_func_attr(xref, idc.FUNCATTR_START)
            if func_start == idaapi.BADADDR:
                continue
            func = idaapi.get_func(xref)
            if func is None:
                continue
            cfunc = idaapi.decompile(func)
            if cfunc is None:
                continue
            if not arg_constant(cfunc, xref):
                continue
            sink_calls.append(
                {
                    "sink_name": sink_name,
                    "sink_ea": sink_ea,
                    "callsite_ea": xref,
                    "caller_func_start": func_start,
                }
            )
            if func_start not in legacy_func_max_callsite:
                legacy_func_max_callsite[func_start] = xref
            else:
                legacy_func_max_callsite[func_start] = max(legacy_func_max_callsite[func_start], xref)
    return sink_calls, legacy_func_max_callsite


def _extract_sink_scope(sink_calls):
    scope = []
    for sink_call in sink_calls:
        sink_caller_start = sink_call["caller_func_start"]
        sink_caller_func = idaapi.get_func(sink_caller_start)
        if sink_caller_func is None:
            continue

        # ✅ 同时获取调用图，用于找根函数
        visited, called_by = _backward_reachable_functions_with_graph(sink_caller_start)
        reachable_func_starts = sorted(visited)

        reachable_funcs = []
        for func_start in reachable_func_starts:
            func = idaapi.get_func(func_start)
            if func is None:
                continue
            reachable_funcs.append(
                {
                    "func_start": func.start_ea,
                    "func_end": func.end_ea,
                    "func_name": idc.get_func_name(func.start_ea),
                }
            )

        # ✅ 找调用链顶端的根函数（入度为0）
        root_funcs = _find_root_functions(visited, called_by)

        scope.append(
            {
                "sink_name": sink_call["sink_name"],
                "sink_ea": sink_call["sink_ea"],
                "sink_callsite_ea": sink_call["callsite_ea"],
                "sink_caller_func_start": sink_caller_start,
                "sink_caller_func_end": sink_caller_func.end_ea,
                "sink_caller_func_name": idc.get_func_name(sink_caller_start),
                "reachable_functions": reachable_funcs,
                "root_functions": sorted(root_funcs),   # ✅ 新增：顶端函数列表
            }
        )
    return scope


INDIRECT_CALL_MNEMONICS = {"jalr", "_jalr", "__jalr", "blx", "blr", "call", "callq", "icall"}


def _merge_intervals(intervals):
    """Merge overlapping or adjacent [start, end) intervals into a minimal list."""
    if not intervals:
        return []
    ordered = sorted((int(s), int(e)) for s, e in intervals)
    merged = [[ordered[0][0], ordered[0][1]]]
    for start, end in ordered[1:]:
        last = merged[-1]
        if start <= last[1]:
            if end > last[1]:
                last[1] = end
        else:
            merged.append([start, end])
    return [(lo, hi) for lo, hi in merged]


def _direct_caller_callsites(callee_start_ea):
    """Return (caller_func_start, callsite_ea) pairs for direct callers of a function."""
    out = []
    for xref in idautils.CodeRefsTo(callee_start_ea, 0):
        caller_func = idaapi.get_func(xref)
        if caller_func is not None:
            out.append((caller_func.start_ea, xref))
    return out


def _count_unresolved_indirect_calls(function_starts):
    """Count indirect call instructions in the given functions (§4.4 metadata)."""
    count = 0
    for func_start in function_starts:
        for insn_ea in idautils.FuncItems(func_start):
            mnem = idc.print_insn_mnem(insn_ea).lower()
            if mnem not in INDIRECT_CALL_MNEMONICS:
                continue
            op_type = idc.get_operand_type(insn_ea, 0)
            if op_type in (idc.o_reg, idc.o_displ, idc.o_phrase):
                count += 1
    return count


def _export_sink_cfg(sink_calls, binary_path):
    """Export real-CFG sink graph as sink_cfg.json payload (§4.3-4.4)."""
    nodes = {}
    edges = []
    edge_keys = set()
    roots = set()
    sinks = []

    visited_all = set()
    for call in sink_calls:
        visited, _ = _backward_reachable_functions_with_graph(call["caller_func_start"])
        visited_all |= visited

    within_called_by = {f: set() for f in visited_all}
    for func_start in visited_all:
        for caller_func_start, _callsite in _direct_caller_callsites(func_start):
            if caller_func_start in visited_all:
                within_called_by[func_start].add(caller_func_start)

    for func_start in sorted(visited_all):
        func = idaapi.get_func(func_start)
        if func is None:
            continue
        if not within_called_by.get(func_start):
            roots.add(func.start_ea)

        flowchart = idaapi.FlowChart(func, flags=0)
        for block in flowchart:
            if block.start_ea not in nodes:
                nodes[block.start_ea] = {
                    "address": block.start_ea,
                    "end_address": block.end_ea,
                    "function_address": func_start,
                    "function_name": idc.get_func_name(func_start),
                    "is_function_entry": block.start_ea == func.start_ea,
                }
            for succ in block.succs():
                key = (block.start_ea, succ.start_ea, "cfg")
                if key not in edge_keys:
                    edge_keys.add(key)
                    edges.append({
                        "source": block.start_ea,
                        "target": succ.start_ea,
                        "kind": "cfg",
                        "weight": 1.0,
                    })

        for callee_start in sorted(visited_all):
            if callee_start == func_start:
                continue
            callee_func = idaapi.get_func(callee_start)
            if callee_func is None:
                continue
            for caller_func_start, xref in _direct_caller_callsites(callee_start):
                if caller_func_start != func_start:
                    continue
                src_block = _find_block_for_ea(flowchart, xref)
                if src_block is None:
                    continue
                key = (src_block.start_ea, callee_start, "call")
                if key not in edge_keys:
                    edge_keys.add(key)
                    edges.append({
                        "source": src_block.start_ea,
                        "target": callee_start,
                        "kind": "call",
                        "weight": 1.0,
                    })

    for call in sink_calls:
        caller_func = idaapi.get_func(call["caller_func_start"])
        if caller_func is None:
            continue
        caller_flowchart = idaapi.FlowChart(caller_func, flags=0)
        sink_block = _find_block_for_ea(caller_flowchart, call["callsite_ea"])
        if sink_block is not None:
            sinks.append({
                "block_address": sink_block.start_ea,
                "callsite_address": call["callsite_ea"],
                "sink_address": call["sink_ea"],
                "sink_name": call["sink_name"],
            })

    cfg = {
        "schema_version": 1,
        "binary": binary_path,
        "nodes": [nodes[a] for a in sorted(nodes)],
        "edges": sorted(edges, key=lambda e: (e["source"], e["target"], e["kind"])),
        "roots": sorted(roots),
        "sinks": sinks,
        "unresolved_indirect_calls": _count_unresolved_indirect_calls(visited_all),
    }
    return cfg


def _write_sink_cfg(cfg):
    """Write sink_cfg.json next to the binary."""
    with open("sink_cfg.json", "w", encoding="utf-8") as file:
        json.dump(cfg, file, indent=2, ensure_ascii=False)
    print(
        "[+] sink_cfg.json written: nodes={} edges={} roots={} sinks={} "
        "unresolved_indirect_calls={}".format(
            len(cfg["nodes"]), len(cfg["edges"]), len(cfg["roots"]),
            len(cfg["sinks"]), cfg["unresolved_indirect_calls"],
        )
    )
    return os.path.abspath("sink_cfg.json")




def _write_legacy_sink_addr(ci_results, bof_results):
    with open('sink_addr.txt', 'w', encoding='utf-8') as file:
        ci_lines = [f"0x{key:X}..0x{value:X}" for key, value in ci_results.items()]
        bof_lines = [f"0x{key:X}..0x{value:X}" for key, value in bof_results.items()]
        all_lines = ci_lines + bof_lines
        file.write(','.join(all_lines))
    print('ci sink func:')
    for key, value in ci_results.items():
        print(f"0x{key:X}..0x{value:X},", end='')
    print('\nbof sink func:')
    for key, value in bof_results.items():
        print(f"0x{key:X}..0x{value:X},", end='')
    print()


def _write_sink_scope(scope_ci, scope_bof):
    """Write sink_scope_addr.txt as merged real reachable-function ranges.

    The filter range comes from the actual reachable functions (adjacent and
    overlapping function ranges are merged) instead of a min-root-to-sink span
    that would implicitly cover unrelated addresses in between.
    """
    intervals = []
    for item in scope_ci + scope_bof:
        for func in item.get("reachable_functions", []):
            intervals.append((func["func_start"], func["func_end"]))

    merged = _merge_intervals(intervals)

    # QEMU dfilter ranges are inclusive on both ends, so subtract 1 from end.
    addr_ranges = sorted({f"0x{lo:X}..0x{hi - 1:X}" for lo, hi in merged})

    with open("sink_scope_addr.txt", "w", encoding="utf-8") as file:
        file.write(",".join(addr_ranges))
    print(f"[+] sink scope merged ranges: {len(addr_ranges)}")


def main():
    binary_path = idaapi.get_input_file_path()
    binary_dir = os.path.dirname(binary_path)
    os.chdir(binary_dir)
    ci_calls, ci_legacy = _collect_sink_calls(CI_SINKS)
    bof_calls, bof_legacy = _collect_sink_calls(BOF_SINKS)

    scope_ci = _extract_sink_scope(ci_calls)
    scope_bof = _extract_sink_scope(bof_calls)

    # _write_legacy_sink_addr(ci_legacy, bof_legacy)
    _write_sink_scope(scope_ci, scope_bof)

    sink_calls = ci_calls + bof_calls
    if not sink_calls:
        print("[-] No sink calls found; skipping sink_cfg.json export.")
        idaapi.qexit(0)

    cfg = _export_sink_cfg(sink_calls, binary_path)
    _write_sink_cfg(cfg)

    idaapi.qexit(0)


if __name__ == '__main__':
    main()
