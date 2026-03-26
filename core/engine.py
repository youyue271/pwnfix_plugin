import ida_funcs
import ida_hexrays
import ida_name
import idautils

from core.context import FunctionContext
from detectors import DEFAULT_DETECTORS
from utils.logger import file_logger


class PwnDetectionEngine:
    def __init__(self, detector_classes=None):
        self.detector_classes = tuple(detector_classes or DEFAULT_DETECTORS)

    def analyze_program(self):
        findings = []

        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if func is None:
                continue

            if (func.flags & ida_funcs.FUNC_LIB) or (func.flags & ida_funcs.FUNC_THUNK):
                continue

            findings.extend(self.analyze_function(func_ea))

        return self._dedupe(findings)

    def analyze_function(self, func_ea):
        func_name = ida_name.get_name(func_ea) or f"sub_{func_ea:x}"

        try:
            cfunc = ida_hexrays.decompile(func_ea)
        except Exception as exc:
            file_logger.error(
                f"Failed to decompile {func_name} at {func_ea:#x}: {exc}"
            )
            return []

        if not cfunc:
            return []

        ctx = FunctionContext(cfunc)
        findings = []

        for detector_cls in self.detector_classes:
            detector = detector_cls(ctx)
            try:
                detector_findings = detector.analyze()
                if detector_findings:
                    file_logger.debug(
                        f"{detector_cls.__name__}: {ctx.function_name} -> "
                        f"{len(detector_findings)} finding(s)"
                    )
                findings.extend(detector_findings)
            except Exception as exc:
                file_logger.error(
                    f"Detector {detector_cls.__name__} failed in "
                    f"{ctx.function_name} at {func_ea:#x}: {exc}"
                )

        return findings

    def _dedupe(self, findings):
        unique = {}
        for finding in findings:
            unique.setdefault(finding.dedupe_key(), finding)
        return sorted(unique.values(), key=lambda item: (item.ea, item.rule_id))
