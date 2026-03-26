from typing import Iterable

import ida_hexrays

from core.models import Vulnerability


class BaseDetector(ida_hexrays.ctree_visitor_t):
    detector_id = "base"
    detector_name = "Base Detector"

    def __init__(self, function_ctx):
        super().__init__(ida_hexrays.CV_FAST)
        self.ctx = function_ctx
        self.alerts = []
        self._seen = set()

    def analyze(self):
        self.apply_to(self.ctx.cfunc.body, None)
        self.finalize()
        self.alerts.sort(key=lambda item: (item.ea, item.rule_id))
        return self.alerts

    def finalize(self):
        return None

    def report(
        self,
        rule_id,
        category,
        severity,
        confidence,
        ea,
        sink,
        description,
        evidence=None,
        recommendations=None,
        fix_actions=None,
    ):
        finding = Vulnerability(
            rule_id=rule_id,
            category=category,
            severity=severity,
            confidence=confidence,
            ea=self.ctx.normalize_ea(ea),
            function_ea=self.ctx.function_ea,
            function_name=self.ctx.function_name,
            sink=sink,
            description=description,
            evidence=tuple(self._normalize_lines(evidence)),
            recommendations=tuple(self._normalize_lines(recommendations)),
            fix_actions=tuple(fix_actions or ()),
        )

        key = finding.dedupe_key()
        if key not in self._seen:
            self._seen.add(key)
            self.alerts.append(finding)

    def _normalize_lines(self, items) -> Iterable[str]:
        if not items:
            return ()
        return [str(item) for item in items if item]
