from dataclasses import dataclass, field
from typing import List, Tuple

from core.models import Vulnerability


@dataclass
class FixCandidate:
    finding: Vulnerability
    action_key: str
    action_label: str
    patchable: bool


@dataclass
class FixApplyResult:
    applied: List[FixCandidate] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)
    failed: List[str] = field(default_factory=list)

    @property
    def applied_count(self):
        return len(self.applied)


class AutoFixEngine:
    """
    One-click patch engine.
    Current patchable rule coverage is intentionally small and conservative.
    """

    def collect_candidates(self, findings: List[Vulnerability]) -> List[FixCandidate]:
        candidates = []
        for finding in findings:
            for action in finding.fix_actions:
                candidates.append(
                    FixCandidate(
                        finding=finding,
                        action_key=action.key,
                        action_label=action.label,
                        patchable=bool(action.patchable),
                    )
                )
        return candidates

    def __init__(self):
        self.applied_patches: List[Tuple[int, bytes]] = []

    def apply_all(self, findings: List[Vulnerability]) -> FixApplyResult:
        result = FixApplyResult()
        for candidate in self.collect_candidates(findings):
            if not candidate.patchable:
                result.skipped.append(
                    f"{candidate.action_key} at {candidate.finding.ea:#x} is suggestion-only."
                )
                continue

            ok, message = self._apply_candidate(candidate)
            if ok:
                result.applied.append(candidate)
            else:
                result.failed.append(message)

        return result

    def _apply_candidate(self, candidate: FixCandidate):
        if candidate.action_key == "disable_second_free_call":
            return self._patch_call_to_nop(candidate.finding.ea, expected_sink="free")

        return (
            False,
            f"Unsupported auto-fix action: {candidate.action_key} at {candidate.finding.ea:#x}",
        )

    def _patch_call_to_nop(self, ea: int, expected_sink: str):
        import ida_bytes
        import ida_ua
        import idc

        mnem = (idc.print_insn_mnem(ea) or "").lower()
        if "call" not in mnem:
            return False, f"{ea:#x}: instruction is not a call ({mnem})."

        operand = (idc.print_operand(ea, 0) or "").lower()
        if expected_sink and expected_sink not in operand and operand:
            return (
                False,
                f"{ea:#x}: call target mismatch. expected={expected_sink}, actual={operand}",
            )

        insn = ida_ua.insn_t()
        size = ida_ua.decode_insn(insn, ea)
        if size <= 0:
            return False, f"{ea:#x}: failed to decode instruction."

        original = bytes(ida_bytes.get_byte(ea + offset) for offset in range(size))

        for offset in range(size):
            ida_bytes.patch_byte(ea + offset, 0x90)

        self.applied_patches.append((ea, original))
        return True, f"{ea:#x}: patched {size} byte(s) to NOP."
