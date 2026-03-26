import ida_hexrays

from core.models import FixAction
from detectors.base import BaseDetector
from utils.hexrays_helper import (
    get_expr_name,
    get_stack_var_size,
    get_string_literal,
    is_stack_var,
    iter_call_args,
)


class StackOverflowDetector(BaseDetector):
    detector_id = "stack"
    detector_name = "Stack Overflow Detector"

    SIZED_WRITES = {
        "read": (1, 2),
        "recv": (1, 2),
        "fgets": (0, 1),
        "memcpy": (0, 2),
        "memmove": (0, 2),
        "strncpy": (0, 2),
    }

    UNBOUNDED_STACK_WRITES = {
        "gets",
        "strcpy",
        "strcat",
        "sprintf",
        "vsprintf",
    }

    def visit_expr(self, expr):
        if expr.op != ida_hexrays.cot_call:
            return 0

        sink = get_expr_name(expr.x)
        if not sink:
            return 0

        if sink in self.UNBOUNDED_STACK_WRITES:
            self._handle_unbounded_stack_write(expr, sink)
        elif sink in self.SIZED_WRITES:
            self._handle_sized_stack_write(expr, sink, *self.SIZED_WRITES[sink])
        elif sink in {"scanf", "isoc99_scanf"}:
            self._handle_scanf(expr, sink)

        return 0

    def _handle_unbounded_stack_write(self, call_expr, sink):
        args = iter_call_args(call_expr)
        if not args:
            return

        dst_arg = args[0]
        if not is_stack_var(dst_arg):
            return

        dst_size = get_stack_var_size(dst_arg)
        size_note = f"stack buffer size is {dst_size} bytes" if dst_size else "stack buffer size is unknown"

        self.report(
            rule_id=f"STACK.UNBOUNDED.{sink.upper()}",
            category="Stack Overflow",
            severity="high",
            confidence="high",
            ea=call_expr.ea,
            sink=sink,
            description=f"{sink} writes to a stack buffer without an explicit bound.",
            evidence=(
                "destination resolves to a stack variable",
                size_note,
                f"dangerous sink: {sink}",
            ),
            recommendations=(
                self._replacement_hint(sink),
                "Prefer APIs that take an explicit destination length.",
            ),
            fix_actions=self._fix_actions_for_unbounded_sink(sink),
        )

    def _handle_sized_stack_write(self, call_expr, sink, dst_index, size_index):
        args = iter_call_args(call_expr)
        if len(args) <= max(dst_index, size_index):
            return

        dst_arg = args[dst_index]
        if not is_stack_var(dst_arg):
            return

        dst_size = get_stack_var_size(dst_arg)
        if dst_size <= 0:
            return

        copy_size = self.ctx.resolve_constant(args[size_index])
        if copy_size is None:
            return

        if copy_size <= dst_size:
            return

        self.report(
            rule_id=f"STACK.BOUNDED.{sink.upper()}",
            category="Stack Overflow",
            severity="high",
            confidence="high",
            ea=call_expr.ea,
            sink=sink,
            description=(
                f"{sink} can copy/read {copy_size} bytes into a {dst_size}-byte stack buffer."
            ),
            evidence=(
                f"destination stack buffer size: {dst_size}",
                f"resolved size argument: {copy_size}",
                "size exceeds local buffer width",
            ),
            recommendations=(
                "Clamp the size argument to the destination buffer width.",
                "If the source length is dynamic, validate it before the sink call.",
            ),
            fix_actions=(
                FixAction(
                    key=f"guard_{sink}_length",
                    label="Add bounds check",
                    description="Insert a min()/if guard so the sink never exceeds the local buffer.",
                    patchable=False,
                ),
            ),
        )

    def _handle_scanf(self, call_expr, sink):
        args = iter_call_args(call_expr)
        if len(args) < 2:
            return

        fmt = get_string_literal(args[0])
        if fmt and not self._has_unbounded_scanf_string(fmt):
            return

        for arg in args[1:]:
            if not is_stack_var(arg):
                continue

            dst_size = get_stack_var_size(arg)
            fmt_note = fmt if fmt else "<dynamic format>"

            self.report(
                rule_id="STACK.UNBOUNDED.SCANF",
                category="Stack Overflow",
                severity="high",
                confidence="medium" if not fmt else "high",
                ea=call_expr.ea,
                sink=sink,
                description=f"{sink} writes a string into a stack buffer without a width limit.",
                evidence=(
                    f"format string: {fmt_note}",
                    "destination resolves to a stack variable",
                    f"destination size: {dst_size or 'unknown'}",
                ),
                recommendations=(
                    "Add a field width to every %s or scanset conversion.",
                    "Consider switching to fgets() plus explicit parsing.",
                ),
                fix_actions=(
                    FixAction(
                        key="tighten_scanf_width",
                        label="Add scanf width",
                        description="Rewrite the format string to include the destination buffer width.",
                        patchable=False,
                    ),
                ),
            )
            return

    def _replacement_hint(self, sink):
        replacements = {
            "gets": "Replace gets() with fgets(buf, sizeof(buf), stdin).",
            "strcpy": "Replace strcpy() with a length-checked copy such as strncpy()/snprintf().",
            "strcat": "Replace strcat() with strncat()/snprintf() and track remaining capacity.",
            "sprintf": "Replace sprintf() with snprintf().",
            "vsprintf": "Replace vsprintf() with vsnprintf().",
        }
        return replacements.get(sink, "Replace the sink with a bounded variant.")

    def _fix_actions_for_unbounded_sink(self, sink):
        replacement_label = {
            "gets": "Swap to fgets",
            "strcpy": "Swap to bounded copy",
            "strcat": "Swap to bounded concat",
            "sprintf": "Swap to snprintf",
            "vsprintf": "Swap to vsnprintf",
        }.get(sink, "Use bounded API")

        return (
            FixAction(
                key=f"replace_{sink}",
                label=replacement_label,
                description=self._replacement_hint(sink),
                patchable=False,
            ),
        )

    def _has_unbounded_scanf_string(self, fmt):
        idx = 0
        while idx < len(fmt):
            if fmt[idx] != "%":
                idx += 1
                continue

            idx += 1
            if idx < len(fmt) and fmt[idx] == "%":
                idx += 1
                continue

            if idx < len(fmt) and fmt[idx] == "*":
                idx += 1

            width_start = idx
            while idx < len(fmt) and fmt[idx].isdigit():
                idx += 1
            has_width = idx > width_start

            while idx < len(fmt) and fmt[idx] in "hljztL":
                idx += 1

            if idx >= len(fmt):
                break

            spec = fmt[idx]
            if spec == "[":
                end = fmt.find("]", idx + 1)
                if end == -1:
                    return True
                if not has_width:
                    return True
                idx = end + 1
                continue

            if spec == "s" and not has_width:
                return True

            idx += 1

        if not fmt:
            return True

        return False
