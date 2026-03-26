import ida_bytes
import ida_hexrays
import ida_name
import ida_nalt
import idaapi


def strip_casts(expr):
    while expr and expr.op == ida_hexrays.cot_cast:
        expr = expr.x
    return expr


def unwrap_expr(expr):
    while expr and expr.op in (ida_hexrays.cot_cast, ida_hexrays.cot_ref):
        expr = expr.x
    return expr


def get_expr_name(expr):
    expr = strip_casts(expr)
    if not expr:
        return None

    if expr.op == ida_hexrays.cot_obj:
        if expr.obj_ea not in (0, idaapi.BADADDR):
            name = ida_name.get_name(expr.obj_ea)
            if name:
                return name.lstrip("._")
        return None

    if expr.op == ida_hexrays.cot_helper:
        if expr.helper:
            return expr.helper.lstrip("._")
        return None

    return None


def get_string_literal(expr):
    expr = strip_casts(expr)
    if not expr:
        return None

    if expr.op == ida_hexrays.cot_obj and expr.obj_ea not in (0, idaapi.BADADDR):
        data = ida_bytes.get_strlit_contents(expr.obj_ea, -1, ida_nalt.STRTYPE_C)
        if data:
            return data.decode("utf-8", errors="ignore")
    return None


def get_var_lvar(expr):
    expr = unwrap_expr(expr)
    if not expr or expr.op != ida_hexrays.cot_var:
        return None

    try:
        return expr.v.getv()
    except AttributeError:
        return None


def is_stack_var(expr):
    lvar = get_var_lvar(expr)
    if lvar:
        try:
            return lvar.is_stk_var()
        except AttributeError:
            pass

    expr = unwrap_expr(expr)
    if expr and expr.op == ida_hexrays.cot_var:
        try:
            return expr.type.is_decl_on_stk()
        except AttributeError:
            pass

    return False


def get_stack_var_size(expr):
    lvar = get_var_lvar(expr)
    if lvar:
        width = getattr(lvar, "width", 0)
        if width:
            return int(width)

    expr = unwrap_expr(expr)
    if expr and expr.op == ida_hexrays.cot_var:
        try:
            size = expr.type.get_size()
            if size and size > 0:
                return int(size)
        except AttributeError:
            pass

    return 0


def get_var_id(expr):
    expr = unwrap_expr(expr)
    if not expr:
        return None

    if expr.op == ida_hexrays.cot_var:
        return f"v_{expr.v.idx}"

    if expr.op == ida_hexrays.cot_obj:
        return f"g_{expr.obj_ea:#x}"

    if expr.op == ida_hexrays.cot_idx:
        base_id = get_var_id(expr.x)
        index_id = get_var_id(expr.y) or "dyn"
        if base_id:
            return f"{base_id}[{index_id}]"
        return None

    if expr.op in (ida_hexrays.cot_memref, ida_hexrays.cot_memptr):
        base_id = get_var_id(expr.x)
        if base_id:
            return f"{base_id}->m{expr.m}"
        return None

    return None


def iter_call_args(call_expr):
    if not call_expr or call_expr.op != ida_hexrays.cot_call:
        return []
    return [call_expr.a[i] for i in range(call_expr.a.size())]


def iter_expr_children(expr):
    if not expr:
        return

    for attr in ("x", "y", "z"):
        child = getattr(expr, attr, None)
        if child:
            yield child

    if expr.op == ida_hexrays.cot_call:
        for arg in iter_call_args(expr):
            yield arg


def contains_var(expr, var_id):
    if not expr or not var_id:
        return False

    if get_var_id(expr) == var_id:
        return True

    for child in iter_expr_children(expr):
        if contains_var(child, var_id):
            return True

    return False


def is_zero_expr(expr):
    expr = strip_casts(expr)
    if not expr:
        return False

    if expr.op == ida_hexrays.cot_num:
        value = get_number_value(expr)
        return value == 0

    if expr.op == ida_hexrays.cot_helper:
        return expr.helper == "NULL"

    return False


def get_number_value(expr):
    expr = strip_casts(expr)
    if not expr or expr.op != ida_hexrays.cot_num:
        return None

    try:
        return int(expr.n.value(expr.type))
    except Exception:
        pass

    try:
        return int(expr.n._value)
    except Exception:
        return None


_BINARY_OPERATIONS = {
    ida_hexrays.cot_add: lambda left, right: left + right,
    ida_hexrays.cot_sub: lambda left, right: left - right,
    ida_hexrays.cot_mul: lambda left, right: left * right,
    ida_hexrays.cot_sdiv: lambda left, right: left // right,
    ida_hexrays.cot_udiv: lambda left, right: left // right,
    ida_hexrays.cot_smod: lambda left, right: left % right,
    ida_hexrays.cot_umod: lambda left, right: left % right,
    ida_hexrays.cot_shl: lambda left, right: left << right,
    ida_hexrays.cot_sshr: lambda left, right: left >> right,
    ida_hexrays.cot_ushr: lambda left, right: left >> right,
    ida_hexrays.cot_band: lambda left, right: left & right,
    ida_hexrays.cot_bor: lambda left, right: left | right,
    ida_hexrays.cot_xor: lambda left, right: left ^ right,
}


def resolve_constant(expr, assignments, max_depth=4, seen=None):
    expr = strip_casts(expr)
    if not expr or max_depth < 0:
        return None

    seen = set(seen or ())

    number = get_number_value(expr)
    if number is not None:
        return number

    if expr.op == ida_hexrays.cot_neg:
        value = resolve_constant(expr.x, assignments, max_depth - 1, seen)
        if value is not None:
            return -value
        return None

    if expr.op == ida_hexrays.cot_var:
        var_id = get_var_id(expr)
        if not var_id or var_id in seen:
            return None

        seen.add(var_id)
        for record in reversed(assignments.get(var_id, [])):
            value = resolve_constant(record.rhs, assignments, max_depth - 1, seen)
            if value is not None:
                return value
        return None

    if expr.op in _BINARY_OPERATIONS:
        left = resolve_constant(expr.x, assignments, max_depth - 1, seen)
        right = resolve_constant(expr.y, assignments, max_depth - 1, seen)
        if left is None or right is None:
            return None

        try:
            return _BINARY_OPERATIONS[expr.op](left, right)
        except ZeroDivisionError:
            return None

    return None
