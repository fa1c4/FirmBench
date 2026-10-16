# CreateFunc.py
# IDAPython: create functions inside executable segments using architecture
# heuristics. Referenced by LLMATaint.py when the .i64 database does not
# contain functions (e.g. stripped firmware binaries whose prologues IDA did
# not auto-detect). Mirrors the heuristic used by Pre_Fuzzing/decompile.py so
# both pre-fuzzing and the taint pipeline see the same function set.
#
# Usage: idat -A -Lida.log -SCreateFunc.py <binary>

import ida_auto
import ida_bytes
import ida_funcs
import ida_segment
import idc

ida_auto.auto_wait()


def detect_arch() -> str:
    try:
        inf = idaapi.get_inf_structure()
        proc = (inf.procname or "").lower()
    except Exception:
        proc = ""

    if "arm" in proc:
        return "ARM"
    if "mips" in proc:
        is_be = False
        try:
            inf = idaapi.get_inf_structure()
            if hasattr(inf, "is_be"):
                is_be = bool(inf.is_be())
            else:
                is_be = bool(idaapi.cvar.inf.is_be())
        except Exception:
            is_be = False
        return "mipsb" if is_be else "mipsl"
    return proc or "unknown"


def _try_add_func(addr) -> bool:
    if addr == idc.BADADDR:
        return False
    if idc.get_func_name(addr):
        return False
    return bool(ida_funcs.add_func(addr))


def create_functions_in_segment(arch, start_addr, end_addr):
    created = 0
    tmp_addr = start_addr
    while tmp_addr != idc.BADADDR and tmp_addr <= end_addr:
        insn = idc.generate_disasm_line(tmp_addr, 0) or ""
        candidate = None

        if arch == "ARM":
            if "PUSH" in insn or "STP             X29, X30" in insn:
                prev = idc.prev_head(tmp_addr)
                prev_insn = idc.generate_disasm_line(prev, 0) or ""
                if "SUB" in prev_insn and ("SP" in prev_insn or "SUB             SP" in prev_insn):
                    candidate = prev
                else:
                    candidate = tmp_addr
        elif arch in ("mipsl", "mipsb"):
            if "addiu" in insn and "$sp" in insn:
                prev = idc.prev_head(tmp_addr)
                prev_insn = idc.generate_disasm_line(prev, 0) or ""
                if "lui" in prev_insn and "$gp" in prev_insn:
                    candidate = prev
                else:
                    candidate = tmp_addr
            elif "addiu" in insn and "$a0" in insn:
                nxt = idc.next_head(tmp_addr)
                next_insn = idc.generate_disasm_line(nxt, 0) or ""
                if "lui" in next_insn and "$gp" in next_insn:
                    candidate = nxt
                else:
                    candidate = tmp_addr

        if candidate is not None and _try_add_func(candidate):
            created += 1
        tmp_addr = idc.next_head(tmp_addr)
    return created


def main():
    arch = detect_arch()
    print("[CreateFunc] arch = {}".format(arch))
    created = 0
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if seg is None:
            continue
        if not (seg.perm & ida_segment.SEGPERM_EXEC):
            continue
        created += create_functions_in_segment(arch, seg.start_ea, seg.end_ea - 1)
    try:
        ida_auto.auto_wait()
    except Exception:
        pass
    print("[CreateFunc] created {} functions".format(created))
    idc.qexit(0)


if __name__ == "__main__":
    import idautils
    import idaapi
    main()
