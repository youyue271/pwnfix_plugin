import ida_hexrays
import ida_name
import idaapi
import ida_funcs
import idautils
import idc
import ida_segment
import re

from core.models import FixAction
from detectors.base import BaseDetector
from utils.hexrays_helper import (
    get_expr_name,
    get_string_literal,
    get_var_id,
    is_stack_var,
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
    ALLOC_SINKS = {"malloc"}
    INIT_CALL_DEST_ARG = {
        "memset": 0,
        "memcpy": 0,
        "memmove": 0,
        "strncpy": 0,
        "strcpy": 0,
        "read": 1,
        "recv": 1,
        "fgets": 0,
    }

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
        self.pending_uninit_container_allocs = {}
        self.initialized_container_allocs = set()
        self.slot_aliases = {}
        self._free_like_cache = {}
        self._ignored_deref_eas = set()
        self._has_flag_offset_mismatch = False
        self._free_call_eas_by_var = {}

    def visit_expr(self, expr):
        if expr.op == ida_hexrays.cot_asg:
            self._handle_assignment(expr)
        elif expr.op == ida_hexrays.cot_call:
            self._handle_call(expr)
        elif expr.op in self.DEREF_OPS:
            self._handle_dereference(expr)
        return 0

    def finalize(self):
        self._report_refcount_bypass_free()
        self._report_clear_offset_mismatch_by_disasm()

        for slot_key, alloc_meta in sorted(
            self.pending_uninit_container_allocs.items(), key=lambda item: item[1]
        ):
            alloc_ea = alloc_meta[0]
            if slot_key in self.initialized_container_allocs:
                continue
            self.report(
                rule_id="HEAP.ALLOC.UNINITIALIZED_CONTAINER",
                category="Heap State Desync",
                severity="medium",
                confidence="medium",
                ea=alloc_ea,
                sink="malloc",
                description=(
                    f"{slot_key} is assigned from malloc() without in-function initialization."
                ),
                evidence=(
                    f"allocation at {alloc_ea:#x}",
                    f"slot candidate: {slot_key}",
                    "no memset/field-initialization on the allocated container observed in this function",
                ),
                recommendations=(
                    "Initialize freshly allocated state blocks before exposing them globally.",
                    "Use calloc() or explicit memset()/field setup for all control fields.",
                ),
                fix_actions=(
                    FixAction(
                        key="init_allocated_container",
                        label="Initialize container state",
                        description="Add explicit zero-initialization for the allocated container structure.",
                        patchable=False,
                    ),
                ),
            )

        for slot_key, free_ea in sorted(
            self.pending_container_clear.items(), key=lambda item: item[1]
        ):
            if self.slot_states.get(slot_key) != self.STATE_FREED:
                continue
            if not self._is_precise_slot(slot_key) and not self._has_flag_offset_mismatch:
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
        raw_pointer_target_slots = self._extract_slot_keys(expr.x, pointer_only=True)
        raw_all_target_slots = self._extract_slot_keys(expr.x, pointer_only=False)
        pointer_target_slots = self._canonicalize_slot_set(raw_pointer_target_slots)
        all_target_slots = self._canonicalize_slot_set(raw_all_target_slots)

        if is_zero_expr(expr.y):
            for slot_key in pointer_target_slots:
                self.slot_states[slot_key] = self.STATE_NULL
                self.slot_last_free.pop(slot_key, None)
                self.pending_container_clear.pop(slot_key, None)
                self.pending_uninit_container_allocs.pop(slot_key, None)
                self.initialized_container_allocs.discard(slot_key)
            return

        if not pointer_target_slots and not all_target_slots:
            return

        rhs = strip_casts(expr.y)
        rhs_sink = ""
        if rhs and rhs.op == ida_hexrays.cot_call:
            rhs_sink = (get_expr_name(rhs.x) or "").lower()

        if rhs_sink in self.ALLOC_SINKS:
            alloc_size = None
            if rhs and rhs.op == ida_hexrays.cot_call:
                rhs_args = iter_call_args(rhs)
                if rhs_args:
                    alloc_size = self.ctx.resolve_constant(rhs_args[0])
            for slot_key in pointer_target_slots:
                if self._is_container_slot(slot_key):
                    if alloc_size is not None and alloc_size > 0x100:
                        continue
                    alloc_ea = self.ctx.normalize_ea(expr.ea)
                    self.pending_uninit_container_allocs[slot_key] = (
                        alloc_ea,
                        alloc_size,
                    )
                    self.initialized_container_allocs.discard(slot_key)

        source_slots = self._canonicalize_slot_set(
            self._extract_slot_keys(expr.y, pointer_only=False)
        )
        self._update_local_aliases(raw_pointer_target_slots, source_slots, rhs_sink)
        inherited = next(
            (
                source_slot
                for source_slot in source_slots
                if self.slot_states.get(source_slot) == self.STATE_FREED
            ),
            None,
        )

        for slot_key in pointer_target_slots:
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
                if rhs_sink not in self.ALLOC_SINKS:
                    self.pending_uninit_container_allocs.pop(slot_key, None)
                    self.initialized_container_allocs.discard(slot_key)

    def _handle_call(self, call_expr):
        sink = (get_expr_name(call_expr.x) or "").lower()
        if not sink:
            return

        args = iter_call_args(call_expr)
        self._mark_container_init_by_call(sink, args)
        self._handle_unbounded_string_sink(call_expr, sink, args)

        if self._is_free_like_sink(sink):
            self._handle_free_call(call_expr, sink, args)
            return

        sink_roles = self.ARG_DEREF_SINKS.get(sink, {})
        if not sink_roles:
            return

        for arg_index, role in sink_roles.items():
            if arg_index >= len(args):
                continue

            slot_keys = self._canonicalize_slot_set(
                self._extract_slot_keys(args[arg_index], pointer_only=False)
            )
            for slot_key in slot_keys:
                if self.slot_states.get(slot_key) != self.STATE_FREED:
                    continue
                if not self._is_precise_slot(slot_key):
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

        free_arg = strip_casts(args[0])
        free_arg_name = get_expr_name(free_arg) or get_var_id(free_arg) or ""
        if free_arg_name:
            self._free_call_eas_by_var.setdefault(self._slot_base(free_arg_name), []).append(
                self.ctx.normalize_ea(call_expr.ea)
            )

        all_slots = []
        for arg in args:
            all_slots.extend(
                self._canonicalize_slot_set(
                    self._extract_slot_keys(arg, pointer_only=False)
                )
            )
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
                self._is_container_slot(slot_key)
                and self._is_precise_slot(slot_key)
                and
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

        slot_keys = self._canonicalize_slot_set(
            self._extract_slot_keys(expr, pointer_only=False)
        )
        for slot_key in slot_keys:
            if self.slot_states.get(slot_key) != self.STATE_FREED:
                continue
            if not self._is_precise_slot(slot_key):
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

    def _mark_container_init_by_call(self, sink, args):
        dest_idx = self.INIT_CALL_DEST_ARG.get(sink)
        if dest_idx is None or dest_idx >= len(args):
            return

        slot_keys = self._canonicalize_slot_set(
            self._extract_slot_keys(args[dest_idx], pointer_only=False)
        )
        for slot_key in slot_keys:
            if slot_key in self.pending_uninit_container_allocs:
                self.initialized_container_allocs.add(slot_key)

    def _report_refcount_bypass_free(self):
        if not self._free_call_eas_by_var:
            return

        guarded_sites_by_var = self._collect_refcount_guarded_free_sites()
        if not guarded_sites_by_var:
            return

        for var_id, free_eas in sorted(self._free_call_eas_by_var.items()):
            if len(free_eas) < 2:
                continue

            guarded_eas = set(guarded_sites_by_var.get(var_id, ()))
            if not guarded_eas:
                continue

            raw_eas = set(free_eas)
            unguarded_eas = sorted(raw_eas - guarded_eas)
            if not unguarded_eas:
                continue

            for free_ea in unguarded_eas:
                self.report(
                    rule_id="HEAP.REFCOUNT.BYPASS_FREE",
                    category="Use After Free",
                    severity="high",
                    confidence="medium",
                    ea=free_ea,
                    sink="free",
                    description=(
                        f"{var_id} has mixed release semantics: direct free on one path and dec-ref guarded free on another."
                    ),
                    evidence=(
                        f"direct free at {free_ea:#x}",
                        f"guarded free sites for {var_id}: "
                        + ", ".join(f"{ea:#x}" for ea in sorted(guarded_eas)),
                        "same free target appears in both guarded and unguarded release paths",
                    ),
                    recommendations=(
                        "Use one ownership strategy per object type: always decref and free only at zero.",
                        "Avoid direct free on potentially shared objects; route all releases through the same helper path.",
                    ),
                    fix_actions=(
                        FixAction(
                            key="enforce_refcount_release",
                            label="Unify refcount release",
                            description="Replace direct free path with decref-and-free-at-zero logic.",
                            patchable=False,
                        ),
                    ),
                )

    def _collect_refcount_guarded_free_sites(self):
        cfunc = getattr(self.ctx, "cfunc", None)
        if not cfunc:
            return {}

        guarded = {}
        outer = self

        class IfGuardVisitor(ida_hexrays.ctree_visitor_t):
            def __init__(self):
                super().__init__(ida_hexrays.CV_FAST)

            def visit_insn(self, insn):
                if insn.op != ida_hexrays.cit_if:
                    return 0

                dec_vars = outer._vars_with_predec_in_expr(insn.cif.expr)
                if not dec_vars:
                    return 0

                for var_id, free_ea in outer._collect_free_calls_from_insn(insn.cif.ithen):
                    if var_id in dec_vars:
                        guarded.setdefault(var_id, set()).add(outer.ctx.normalize_ea(free_ea))

                for var_id, free_ea in outer._collect_free_calls_from_insn(insn.cif.ielse):
                    if var_id in dec_vars:
                        guarded.setdefault(var_id, set()).add(outer.ctx.normalize_ea(free_ea))
                return 0

        try:
            IfGuardVisitor().apply_to(cfunc.body, None)
        except Exception:
            return {}
        return guarded

    def _vars_with_predec_in_expr(self, expr):
        vars_with_dec = set()
        outer = self

        class DecExprVisitor(ida_hexrays.ctree_visitor_t):
            def __init__(self):
                super().__init__(ida_hexrays.CV_FAST)

            def visit_expr(self, e):
                if e.op not in (ida_hexrays.cot_predec, ida_hexrays.cot_postdec):
                    return 0
                target = strip_casts(getattr(e, "x", None))
                var_id = get_var_id(target)
                if var_id:
                    vars_with_dec.add(outer._slot_base(var_id))
                return 0

        if not expr:
            return vars_with_dec
        try:
            DecExprVisitor().apply_to(expr, None)
        except Exception:
            return set()
        return vars_with_dec

    def _collect_free_calls_from_insn(self, insn):
        if not insn:
            return []

        free_calls = []
        outer = self

        class FreeCallVisitor(ida_hexrays.ctree_visitor_t):
            def __init__(self):
                super().__init__(ida_hexrays.CV_FAST)

            def visit_expr(self, e):
                if e.op != ida_hexrays.cot_call:
                    return 0
                sink = (get_expr_name(e.x) or "").lower()
                if sink != "free":
                    return 0

                args = iter_call_args(e)
                if not args:
                    return 0

                var_id = get_var_id(strip_casts(args[0]))
                if not var_id:
                    return 0

                free_calls.append((outer._slot_base(var_id), e.ea))
                return 0

        try:
            FreeCallVisitor().apply_to(insn, None)
        except Exception:
            return []
        return free_calls

    def _report_clear_offset_mismatch_by_disasm(self):
        func = ida_funcs.get_func(self.ctx.function_ea)
        if not func:
            return

        clear_ea = None
        touch_208 = False
        free_seen = False

        for ea in idautils.FuncItems(func.start_ea):
            mnem = (idc.print_insn_mnem(ea) or "").lower()
            op0 = (idc.print_operand(ea, 0) or "").lower()
            op1 = (idc.print_operand(ea, 1) or "").lower()

            if "+208h" in op0 or "+208h" in op1:
                touch_208 = True
            if "call" in mnem and "free" in op0:
                free_seen = True
            if (
                mnem == "mov"
                and "byte ptr" in op0
                and "+200h" in op0
                and op1 in {"0", "0h"}
            ):
                clear_ea = ea

        if not (clear_ea and touch_208 and free_seen):
            return

        self.report(
            rule_id="HEAP.FLAG_OFFSET_MISMATCH",
            category="Heap State Desync",
            severity="high",
            confidence="high",
            ea=clear_ea,
            sink="assign",
            description=(
                "Post-free cleanup writes to +0x200 byte while transaction/state logic uses +0x208."
            ),
            evidence=(
                f"suspicious clear at {clear_ea:#x}: byte ptr [base+0x200] = 0",
                "same function also accesses base+0x208 as state flag",
                "free() call observed in the same state-transition path",
            ),
            recommendations=(
                "Clear the actual state flag field (likely +0x208), not the pointer field low byte.",
                "Keep transaction pointer and transaction flag updates consistent after free.",
            ),
            fix_actions=(
                FixAction(
                    key="fix_state_flag_offset",
                    label="Fix state flag offset",
                    description="Patch cleanup store target from +0x200 to the real flag offset (+0x208).",
                    patchable=False,
                ),
            ),
        )
        self._has_flag_offset_mismatch = True

    def _handle_unbounded_string_sink(self, call_expr, sink, args):
        if sink != "printf" or len(args) < 2:
            return

        fmt = get_string_literal(args[0])
        if not fmt:
            return

        for fmt_s_index in self._format_s_arg_indices(fmt):
            arg_index = 1 + fmt_s_index
            if arg_index >= len(args):
                continue

            arg = args[arg_index]
            if not self._is_risky_heap_cstring_arg(arg):
                continue

            self.report(
                rule_id="HEAP.CSTR.UNBOUNDED_PRINTF",
                category="Information Leak",
                severity="high",
                confidence="medium",
                ea=call_expr.ea,
                sink=sink,
                description=(
                    f"printf consumes a heap-derived string via unbounded %s (arg#{arg_index})."
                ),
                evidence=(
                    f"format string: {fmt}",
                    f"argument index: {arg_index}",
                    "heap-derived pointer may be non-NUL-terminated",
                ),
                recommendations=(
                    "Use precision-limited formatting (e.g. %.Ns) or tracked-length output APIs.",
                    "Ensure copied heap buffers are NUL-terminated before %s sinks.",
                ),
                fix_actions=(
                    FixAction(
                        key="bound_printf_string",
                        label="Bound %s output",
                        description="Replace unbounded %s with precision-limited output tied to the stored length.",
                        patchable=False,
                    ),
                ),
            )

    def _format_s_arg_indices(self, fmt):
        indices = []
        fmt_arg_index = 0
        i = 0
        while i < len(fmt):
            if fmt[i] != "%":
                i += 1
                continue

            i += 1
            if i < len(fmt) and fmt[i] == "%":
                i += 1
                continue

            while i < len(fmt) and fmt[i] in "-+ #0":
                i += 1

            while i < len(fmt) and fmt[i].isdigit():
                i += 1

            has_precision = False
            if i < len(fmt) and fmt[i] == ".":
                has_precision = True
                i += 1
                while i < len(fmt) and fmt[i].isdigit():
                    i += 1

            while i < len(fmt) and fmt[i] in "hljztL":
                i += 1

            if i >= len(fmt):
                break

            spec = fmt[i]
            if spec == "s" and not has_precision:
                indices.append(fmt_arg_index)

            if spec not in ("n",):
                fmt_arg_index += 1

            i += 1

        return indices

    def _is_risky_heap_cstring_arg(self, expr):
        if not expr:
            return False
        if get_string_literal(expr):
            return False
        if is_stack_var(expr):
            return False

        base = unwrap_expr(strip_casts(expr))
        if not self._is_pointer_expr(base):
            return False

        if base.op in (
            ida_hexrays.cot_memref,
            ida_hexrays.cot_memptr,
            ida_hexrays.cot_ptr,
            ida_hexrays.cot_idx,
        ):
            return True

        slot_keys = self._extract_slot_keys(base, pointer_only=False)
        return any(self._is_container_slot(key) for key in slot_keys)

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
            if pointer_only and not self._is_pointer_expr(expr):
                return None
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

    def _update_local_aliases(self, raw_pointer_targets, source_slots, rhs_sink):
        container_sources = [slot for slot in source_slots if self._is_container_slot(slot)]
        for raw_slot in raw_pointer_targets:
            base = self._slot_base(raw_slot)
            if not base.startswith("v_"):
                continue
            if container_sources:
                self.slot_aliases[base] = container_sources[0]
                continue
            if rhs_sink in self.ALLOC_SINKS or not source_slots:
                self.slot_aliases.pop(base, None)

    def _canonicalize_slot_set(self, slots):
        return {self._canonicalize_slot_key(slot) for slot in slots if slot}

    def _canonicalize_slot_key(self, slot_key):
        if not slot_key:
            return slot_key
        base = self._slot_base(slot_key)
        alias = self.slot_aliases.get(base)
        if not alias:
            return slot_key
        if slot_key == base:
            return alias
        suffix = slot_key[len(base) :]
        if suffix.startswith("[") or suffix.startswith("->"):
            return alias
        return alias + suffix

    def _slot_base(self, slot_key):
        if not slot_key:
            return ""
        for sep in ("[", "->"):
            idx = slot_key.find(sep)
            if idx != -1:
                return slot_key[:idx]
        return slot_key

    def _is_pointer_expr(self, expr):
        expr = strip_casts(expr)
        if not expr:
            return False
        try:
            return bool(expr.type and expr.type.is_ptr())
        except Exception:
            return False

    def _is_container_slot(self, slot_key):
        if "[" in slot_key:
            return True
        if not slot_key.startswith("g_"):
            return False
        try:
            addr = int(slot_key[2:], 16)
            seg = ida_segment.getseg(addr)
            if not seg:
                return False
            return bool(seg.perm & ida_segment.SEGPERM_WRITE)
        except Exception:
            return False

    def _is_precise_slot(self, slot_key):
        return "[dyn]" not in slot_key and "[*]" not in slot_key

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
