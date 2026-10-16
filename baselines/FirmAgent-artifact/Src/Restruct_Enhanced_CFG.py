# Restruct_Enhanced_CFG.py
# IDAPython: rebuild the function/source map used by the LLM taint pipeline.
#
# Produces, next to the target binary:
#   <bin>_functions_info.txt   one line per function:
#       0x<addr> name: <name> seg: <segment> source_function: <True|False>
#   <bin>_origin_strs.txt      exported strings (input to later LLM stages)
#
# A function is flagged as a source function when it invokes one of the
# firmware input APIs (websGetVar / get_cgi / ...), when its name matches a
# known input-handler pattern, or when it is listed in an optional
# source_funcs.txt file placed next to the binary (one name per line).
#
# Usage: idat -A -Lida.log -SRestruct_Enhanced_CFG.py <binary>

import os
import re

import ida_auto
import ida_bytes
import ida_funcs
import ida_segment
import idautils
import idc

ida_auto.auto_wait()

# Input APIs from TaintChecker.py plus common firmware aliases.
SOURCE_API_NAMES = [
    "websGetVar", "webGetVar", "j_websGetVar", "websGetVarN", "webGetVarString",
    "json_object_get_string", "get_cgi", "json_string_value",
    "cgiGetValue", "cgiGetVar", "boaGetVar", "boa_get_var", "boaGetValue",
    "getValue", "GetValue", "GetValueEx", "httpGetEnv", "getenv",
    "nvram_get", "nvram_safe_get", "acosNvramConfig_get",
]

SOURCE_NAME_PATTERNS = re.compile(
    r"(get_cgi|webs?getvar|cgiget|boaget|getvalue|_get_var|_getvalue|"
    r"getparam|get_param|getinput|get_input|httpget|readvar)",
    re.IGNORECASE,
)


def _load_extra_source_funcs(bin_dir):
    names = set()
    extra_file = os.path.join(bin_dir, "source_funcs.txt")
    if os.path.exists(extra_file):
        with open(extra_file, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    names.add(line)
    return names


def _collect_source_func_addrs(extra_names):
    addrs = set()
    for name in SOURCE_API_NAMES:
        ea = idc.get_name_ea_simple(name)
        if ea == idc.BADADDR:
            continue
        for xref in idautils.CodeRefsTo(ea, 0):
            func = ida_funcs.get_func(xref)
            if func is not None:
                addrs.add(func.start_ea)
    for name in extra_names:
        ea = idc.get_name_ea_simple(name)
        if ea == idc.BADADDR:
            continue
        func = ida_funcs.get_func(ea)
        if func is not None:
            addrs.add(func.start_ea)
    return addrs


def _segment_name(func):
    seg = ida_segment.getseg(func.start_ea)
    if seg is None:
        return ""
    return ida_segment.get_segm_name(seg) or ""


def main():
    binary_path = idaapi.get_input_file_path()
    binary_dir = os.path.dirname(binary_path)
    binary_name = os.path.basename(binary_path)
    if binary_dir:
        os.chdir(binary_dir)

    extra_names = _load_extra_source_funcs(binary_dir)
    source_addrs = _collect_source_func_addrs(extra_names)

    functions = list(idautils.Functions())
    funcs_info_path = "{}_functions_info.txt".format(binary_path)
    with open(funcs_info_path, "w", encoding="utf-8") as fh:
        for func_ea in functions:
            func = ida_funcs.get_func(func_ea)
            if func is None:
                continue
            name = idc.get_func_name(func.start_ea) or "sub_{:X}".format(func.start_ea)
            is_source = func.start_ea in source_addrs
            if not is_source and SOURCE_NAME_PATTERNS.search(name):
                is_source = True
            fh.write("{} name: {} seg: {} source_function: {}\n".format(
                func.start_ea, name, _segment_name(func), is_source))

    strings_path = "{}_origin_strs.txt".format(binary_path)
    with open(strings_path, "w", encoding="utf-8") as fh:
        fh.write("# strings exported from {}\n".format(binary_name))
        try:
            for s in idautils.Strings():
                try:
                    text = str(s)
                except Exception:
                    continue
                if text:
                    fh.write(text + "\n")
        except Exception as err:
            fh.write("# strings export failed: {}\n".format(err))

    print("[Restruct] functions: {} source functions: {}".format(
        len(functions), len(source_addrs)))
    print("[Restruct] wrote {} and {}".format(funcs_info_path, strings_path))
    idc.qexit(0)


if __name__ == "__main__":
    import idaapi
    main()
