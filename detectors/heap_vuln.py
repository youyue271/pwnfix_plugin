import ida_hexrays
import ida_name
import idaapi

from core.models import FixAction
from detectors.base import BaseDetector
from utils.hexrays_helper import (
    get_expr_name,
    get_var_id,
    is_zero_expr,
    iter_call_args,
    iter_expr_children,
    strip_casts,
    unwrap_expr,
)


class HeapVulnDetector(BaseDetector):
    detector_id = "heap"
    detector_name = "Heap Misuse Detector"

    FREE_SINKS = {"free"}

    STATE_FREED = "FREED"
    STATE_NULL = "NULL"
    STATE_UNKNOWN = "UNKNOWN"

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
        self.slot_states = {}
        self.slot_last_free = {}
        self.pending_container_clear = {}
        self._free_like_cache = {}
        self._ignored_deref_eas = set()

    def visit_expr(self, expr):
        if expr.op == ida_hexrays.cot_asg:
            self._handle_assignment(expr)
        elif expr.op == ida_hexrays.cot_call:
            self._handle_call(expr)
        elif expr.op in self.DEREF_OPS:
            self._handle_dereference(expr)
        return 0

    def finalize(self):
        for slot_key, free_ea in sorted(
            self.pending_container_clear.items(), key=lambda item: item[1]
        ):
            if self.slot_states.get(slot_key) != self.STATE_FREED:
                continue
            self.report(
                rule_id="HEAP.FREE.NOT_CLEARED",
                category="Heap State Desync",
                severity="high",
                confidence="medium",
                ea=free_ea,
                sink="free",
                description=(
                    f"{slot_key} is freed but the pointer slot is not cleared to NULL."
                ),
                evidence=(
                    f"free at {free_ea:#x}",
                    f"slot candidate: {slot_key}",
                    "no pointer-slot NULL assignment detected later in this function",
                ),
                recommendations=(
                    "After free(slot[idx]), immediately set slot[idx] = NULL.",
                    "Keep pointer-slot and size/state-slot updates consistent in delete paths.",
                ),
                fix_actions=(
                    FixAction(
                        key="clear_freed_slot",
                        label="Null out freed slot",
                        description="Insert a NULL write for the pointer slot immediately after free.",
                        patchable=False,
                    ),
                ),
            )

    def _handle_assignment(self, expr):
        target_slots = self._extract_slot_keys(expr.x, pointer_only=True)
        if not target_slots:
            return

        if is_zero_expr(expr.y):
            for slot_key in target_slots:
                self.slot_states[slot_key] = self.STATE_NULL
                self.slot_last_free.pop(slot_key, None)
                self.pending_container_clear.pop(slot_key, None)
            return

        source_slots = self._extract_slot_keys(expr.y, pointer_only=False)
        inherited = next(
            (
                source_slot
                for source_slot in source_slots
                if self.slot_states.get(source_slot) == self.STATE_FREED
            ),
            None,
        )

        for slot_key in target_slots:
            if inherited:
                free_ea = self.slot_last_free.get(inherited)
                self.slot_states[slot_key] = self.STATE_FREED
                if free_ea is not None:
                    self.slot_last_free[slot_key] = free_ea
                if self._is_container_slot(slot_key):
                    self.pending_container_clear[slot_key] = free_ea or self.ctx.normalize_ea(
                        expr.ea
                    )
            else:
                self.slot_states[slot_key] = self.STATE_UNKNOWN
                self.slot_last_free.pop(slot_key, None)
                self.pending_container_clear.pop(slot_key, None)

    def _handle_call(self, call_expr):
        sink = (get_expr_name(call_expr.x) or "").lower()
        if not sink:
            return

        args = iter_call_args(call_expr)

        if self._is_free_like_sink(sink):
            self._handle_free_call(call_expr, sink, args)
            return

        sink_roles = self.ARG_DEREF_SINKS.get(sink, {})
        if not sink_roles:
            return

        for arg_index, role in sink_roles.items():
            if arg_index >= len(args):
                continue

            for slot_key in self._extract_slot_keys(args[arg_index], pointer_only=False):
                if self.slot_states.get(slot_key) != self.STATE_FREED:
                    continue

                free_ea = self.slot_last_free.get(slot_key)
                use_ea = self.ctx.normalize_ea(call_expr.ea)
                if free_ea is not None and use_ea <= free_ea:
                    continue
                self.report(
                    rule_id="HEAP.UAF.CALL",
                    category="Use After Free",
                    severity="high",
                    confidence="high",
                    ea=use_ea,
                    sink=sink,
                    description=(
                        f"{slot_key} is passed to {sink} after free; the sink {role} potentially accesses freed heap memory."
                    ),
                    evidence=(
                        f"pointer slot: {slot_key}",
                        f"free observed at {free_ea:#x}" if free_ea else "free observed earlier in function",
                        f"sink: {sink}",
                        f"argument index: {arg_index}",
                    ),
                    recommendations=(
                        "Do not reuse a pointer after free; reacquire or reinitialize ownership first.",
                        "Clear the pointer slot to NULL immediately after free.",
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

    def _handle_free_call(self, call_expr, sink, args):
        if not args:
            return

        all_slots = []
        for arg in args:
            all_slots.extend(self._extract_slot_keys(arg, pointer_only=False))
            self._mark_expr_eas_for_deref_ignore(arg)

        if not all_slots:
            return

        container_slots = [slot for slot in all_slots if self._is_container_slot(slot)]
        freed_slots = container_slots or all_slots
        if not freed_slots:
            return

        free_ea = self.ctx.normalize_ea(call_expr.ea)
        for slot_key in freed_slots:
            previous_free_ea = self.slot_last_free.get(slot_key)
            if (
                self.slot_states.get(slot_key) == self.STATE_FREED
                and previous_free_ea is not None
            ):
                self.report(
                    rule_id="HEAP.DOUBLE_FREE",
                    category="Double Free",
                    severity="high",
                    confidence="high",
                    ea=call_expr.ea,
                    sink=sink,
                    description=(
                        f"{slot_key} is freed again before being reassigned or cleared."
                    ),
                    evidence=(
                        f"pointer slot: {slot_key}",
                        f"first free at {previous_free_ea:#x}",
                        f"second free at {free_ea:#x}",
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

            self.slot_states[slot_key] = self.STATE_FREED
            self.slot_last_free[slot_key] = free_ea
            if self._is_container_slot(slot_key):
                self.pending_container_clear[slot_key] = free_ea

    def _handle_dereference(self, expr):
        if self.ctx.normalize_ea(expr.ea) in self._ignored_deref_eas:
            return

        for slot_key in self._extract_slot_keys(expr, pointer_only=False):
            if self.slot_states.get(slot_key) != self.STATE_FREED:
                continue

            free_ea = self.slot_last_free.get(slot_key)
            deref_ea = self.ctx.normalize_ea(expr.ea)
            if free_ea is not None and deref_ea <= free_ea:
                continue
            self.report(
                rule_id="HEAP.UAF.DEREF",
                category="Use After Free",
                severity="high",
                confidence="high",
                ea=deref_ea,
                sink="deref",
                description=f"{slot_key} is dereferenced after it has been freed.",
                evidence=(
                    f"pointer slot: {slot_key}",
                    f"free observed at {free_ea:#x}" if free_ea else "free observed earlier in function",
                    "dereference occurs on stale heap data",
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

    def _extract_slot_keys(self, expr, pointer_only):
        found = set()
        self._walk_slot_keys(strip_casts(expr), found, pointer_only=pointer_only)
        indexed_bases = {
            key.split("[", 1)[0] for key in found if "[" in key and key.split("[", 1)[0]
        }
        if not indexed_bases:
            return found
        return {key for key in found if key not in indexed_bases}

    def _walk_slot_keys(self, expr, found, pointer_only):
        if not expr:
            return

        slot_key = self._slot_key_from_expr(expr, pointer_only=pointer_only)
        if slot_key:
            found.add(slot_key)

        for child in iter_expr_children(expr):
            self._walk_slot_keys(strip_casts(child), found, pointer_only=pointer_only)

    def _slot_key_from_expr(self, expr, pointer_only):
        expr = unwrap_expr(expr)
        if not expr:
            return None

        direct_id = get_var_id(expr)
        if expr.op in (ida_hexrays.cot_var, ida_hexrays.cot_obj):
            if pointer_only and not self._is_pointer_expr(expr):
                return None
            return direct_id

        if expr.op in (
            ida_hexrays.cot_idx,
            ida_hexrays.cot_memref,
            ida_hexrays.cot_memptr,
        ):
            if pointer_only and not self._is_pointer_expr(expr):
                return None
            return direct_id

        if expr.op == ida_hexrays.cot_ptr:
            return self._build_symbolic_slot_key(expr)

        return None

    def _build_symbolic_slot_key(self, expr):
        global_ids = set()
        local_ids = set()
        self._collect_symbol_ids(expr, global_ids, local_ids)
        if global_ids:
            base = sorted(global_ids)[0]
            index_ids = sorted(local_ids)
            if index_ids:
                return f"{base}[{','.join(index_ids)}]"
            return f"{base}[*]"
        if local_ids:
            return sorted(local_ids)[0]
        return None

    def _collect_symbol_ids(self, expr, global_ids, local_ids):
        expr = unwrap_expr(expr)
        if not expr:
            return

        var_id = get_var_id(expr)
        if var_id:
            if var_id.startswith("g_"):
                global_ids.add(var_id)
            elif var_id.startswith("v_"):
                local_ids.add(var_id)

        for child in iter_expr_children(expr):
            self._collect_symbol_ids(child, global_ids, local_ids)

    def _is_pointer_expr(self, expr):
        expr = strip_casts(expr)
        if not expr:
            return False
        try:
            return bool(expr.type and expr.type.is_ptr())
        except Exception:
            return False

    def _is_container_slot(self, slot_key):
        return slot_key.startswith("g_") or "[" in slot_key

    def _mark_expr_eas_for_deref_ignore(self, expr):
        expr = strip_casts(expr)
        if not expr:
            return
        ea = self.ctx.normalize_ea(expr.ea)
        if ea not in (0, idaapi.BADADDR):
            self._ignored_deref_eas.add(ea)
        for child in iter_expr_children(expr):
            self._mark_expr_eas_for_deref_ignore(child)

    def _is_free_like_sink(self, sink):
        if sink in self.FREE_SINKS:
            return True

        cached = self._free_like_cache.get(sink)
        if cached is not None:
            return cached

        is_free_like = False
        if sink.startswith("sub_"):
            callee_ea = ida_name.get_name_ea(idaapi.BADADDR, sink)
            if callee_ea not in (idaapi.BADADDR, 0):
                try:
                    callee = ida_hexrays.decompile(callee_ea)
                    if callee:
                        class FreeLikeVisitor(ida_hexrays.ctree_visitor_t):
                            def __init__(self):
                                super().__init__(ida_hexrays.CV_FAST)
                                self.hit = False

                            def visit_expr(self, expr):
                                if expr.op != ida_hexrays.cot_call:
                                    return 0
                                name = (get_expr_name(expr.x) or "").lower()
                                if name in {"free", "munmap", "cfree"}:
                                    self.hit = True
                                return 0

                        checker = FreeLikeVisitor()
                        checker.apply_to(callee.body, None)
                        is_free_like = checker.hit
                except Exception:
                    is_free_like = False

        self._free_like_cache[sink] = is_free_like
        return is_free_like
