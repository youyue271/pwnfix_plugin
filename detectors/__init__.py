from detectors.heap_vuln import HeapVulnDetector
from detectors.stack_overflow import StackOverflowDetector

DEFAULT_DETECTORS = (
    StackOverflowDetector,
    HeapVulnDetector,
)

__all__ = ["DEFAULT_DETECTORS", "HeapVulnDetector", "StackOverflowDetector"]
