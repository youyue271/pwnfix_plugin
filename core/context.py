from dataclasses import dataclass
from typing import Dict, List

import idaapi
import ida_hexrays
import ida_name

from utils.hexrays_helper import get_expr_name, get_var_id, resolve_constant


@dataclass
class AssignmentRecord:
    ea: int
    rhs: object


@dataclass
class CallRecord:
    ea: int
    name: str
    expr: object


class FunctionContext:
    def __init__(self, cfunc):
        self.cfunc = cfunc
        self.function_ea = int(
            getattr(cfunc, "entry_ea", getattr(cfunc, "ea", idaapi.BADADDR))
        )
        self.function_name = ida_name.get_name(self.function_ea) or (
            f"sub_{self.function_ea:x}"
        )
        self.assignments: Dict[str, List[AssignmentRecord]] = {}
        self.calls: List[CallRecord] = []
        self._build_indexes()

    def normalize_ea(self, ea):
        if ea in (None, idaapi.BADADDR):
            return self.function_ea
        return int(ea)

    def resolve_constant(self, expr, max_depth=4):
        return resolve_constant(expr, self.assignments, max_depth=max_depth)

    def _build_indexes(self):
        class IndexVisitor(ida_hexrays.ctree_visitor_t):
            def __init__(self, ctx):
                super().__init__(ida_hexrays.CV_FAST)
                self.ctx = ctx

            def visit_expr(self, expr):
                ea = self.ctx.normalize_ea(expr.ea)

                if expr.op == ida_hexrays.cot_asg:
                    var_id = get_var_id(expr.x)
                    if var_id:
                        self.ctx.assignments.setdefault(var_id, []).append(
                            AssignmentRecord(ea=ea, rhs=expr.y)
                        )
                elif expr.op == ida_hexrays.cot_call:
                    self.ctx.calls.append(
                        CallRecord(
                            ea=ea,
                            name=get_expr_name(expr.x) or "<indirect>",
                            expr=expr,
                        )
                    )
                return 0

        IndexVisitor(self).apply_to(self.cfunc.body, None)
