from dataclasses import dataclass, field
from typing import Tuple


@dataclass(frozen=True)
class FixAction:
    key: str
    label: str
    description: str
    patchable: bool = False


@dataclass
class Vulnerability:
    rule_id: str
    category: str
    severity: str
    confidence: str
    ea: int
    function_ea: int
    function_name: str
    sink: str
    description: str
    evidence: Tuple[str, ...] = field(default_factory=tuple)
    recommendations: Tuple[str, ...] = field(default_factory=tuple)
    fix_actions: Tuple[FixAction, ...] = field(default_factory=tuple)

    def dedupe_key(self):
        return (
            self.rule_id,
            self.ea,
            self.function_ea,
            self.sink,
            self.description,
        )
