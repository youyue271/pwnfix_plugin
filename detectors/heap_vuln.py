import ida_hexrays

from core.models import FixAction
from detectors.base import BaseDetector
from utils.hexrays_helper import contains_var, get_expr_name, get_var_id, iter_call_args


class HeapVulnDetector(BaseDetector):
    detector_id = "heap"
    detector_name = "Heap Misuse Detector"

    ARG_DEREF_SINKS = {
        "memcpy": {0: "writes to", 1: "reads from"},
        "memmove": {0: "writes to", 1: "reads from"},
        "memset": {0: "writes to"},
        "strcpy": {0: "writes to", 1: "reads from"},
        "strncpy": {0: "writes to", 1: "reads from"},
        "strcat": {0: "reads/writes to", 1: "reads from"},
        "strlen": {0: "reads from"},
        "strcmp": {0: "reads from", 1: "reads from"},
        "puts": {0: "reads from"},
        "read": {1: "writes to"},
        "recv": {1: "writes to"},
        "write": {1: "reads from"},
        "send": {1: "reads from"},
        "fgets": {0: "writes to"},
        "realloc": {0: "reads from"},
    }

    DEREF_OPS = (
        ida_hexrays.cot_ptr,
        ida_hexrays.cot_memref,
        ida_hexrays.cot_memptr,
        ida_hexrays.cot_idx,
    )

    def __init__(self, function_ctx):
        super().__init__(function_ctx)
        self.freed_bindings = {}

    def visit_expr(self, expr):
        if expr.op == ida_hexrays.cot_asg:
            self._handle_assignment(expr)
        elif expr.op == ida_hexrays.cot_call:
            self._handle_call(expr)
        elif expr.op in self.DEREF_OPS:
            self._handle_dereference(expr)
        return 0

    def _handle_assignment(self, expr):
        target_id = get_var_id(expr.x)
        if target_id and target_id in self.freed_bindings:
            self.freed_bindings.pop(target_id, None)

    def _handle_call(self, call_expr):
        sink = get_expr_name(call_expr.x)
        if not sink:
            return

        args = iter_call_args(call_expr)

        if sink == "free":
            if not args:
                return
            freed_id = get_var_id(args[0])
            if not freed_id:
                return

            previous_free_ea = self.freed_bindings.get(freed_id)
            if previous_free_ea is not None:
                self.report(
                    rule_id="HEAP.DOUBLE_FREE",
                    category="Double Free",
                    severity="high",
                    confidence="high",
                    ea=call_expr.ea,
                    sink=sink,
                    description=(
                        f"{freed_id} is freed again before being reassigned or cleared."
                    ),
                    evidence=(
                        f"first free at {previous_free_ea:#x}",
                        f"second free at {self.ctx.normalize_ea(call_expr.ea):#x}",
                    ),
                    recommendations=(
                        "Clear ownership after free and guard repeated cleanup paths.",
                        "Set the pointer or slot to NULL immediately after free.",
                    ),
                    fix_actions=(
                        FixAction(
                            key="disable_second_free_call",
                            label="NOP second free call",
                            description="Patch the second free callsite to NOP bytes.",
                            patchable=True,
                        ),
                    ),
                )

            self.freed_bindings[freed_id] = self.ctx.normalize_ea(call_expr.ea)
            return

        sink_roles = self.ARG_DEREF_SINKS.get(sink, {})
        if not sink_roles:
            return

        for arg_index, role in sink_roles.items():
            if arg_index >= len(args):
                continue

            freed_id = self._find_freed_binding(args[arg_index])
            if not freed_id:
                continue

            self.report(
                rule_id="HEAP.UAF.CALL",
                category="Use After Free",
                severity="high",
                confidence="high",
                ea=call_expr.ea,
                sink=sink,
                description=(
                    f"{freed_id} is passed to {sink} after free; the sink {role} potentially freed heap memory."
                ),
                evidence=(
                    f"free observed at {self.freed_bindings[freed_id]:#x}",
                    f"sink: {sink}",
                    f"argument index: {arg_index}",
                ),
                recommendations=(
                    "Do not reuse a pointer after free; reacquire or reinitialize ownership first.",
                    "Clear the pointer after free so stale uses fail fast.",
                ),
                fix_actions=(
                    FixAction(
                        key="split_uaf_path",
                        label="Guard freed pointer",
                        description="Insert a NULL/state check before the sink and stop using stale heap references.",
                        patchable=False,
                    ),
                ),
            )

    def _handle_dereference(self, expr):
        base_expr = getattr(expr, "x", None)
        freed_id = self._find_freed_binding(base_expr)
        if not freed_id:
            return

        self.report(
            rule_id="HEAP.UAF.DEREF",
            category="Use After Free",
            severity="high",
            confidence="high",
            ea=expr.ea,
            sink="deref",
            description=f"{freed_id} is dereferenced after it has been freed.",
            evidence=(
                f"free observed at {self.freed_bindings[freed_id]:#x}",
                "dereference occurs on the stale heap pointer",
            ),
            recommendations=(
                "Remove the dereference or move it before the free site.",
                "Reset the pointer after free and reload it from a valid allocator path.",
            ),
            fix_actions=(
                FixAction(
                    key="remove_stale_deref",
                    label="Remove stale deref",
                    description="Reorder the free/use sequence so the pointer is not dereferenced after free.",
                    patchable=False,
                ),
            ),
        )

    def _find_freed_binding(self, expr):
        if not expr:
            return None

        direct_id = get_var_id(expr)
        if direct_id in self.freed_bindings:
            return direct_id

        for freed_id in self.freed_bindings:
            if contains_var(expr, freed_id):
                return freed_id

        return None
