import sys
import os

for mod in list(sys.modules.keys()):
    if mod.startswith("core.") or mod.startswith("detectors.") or mod.startswith("utils."):
        del sys.modules[mod]

script_dir = os.path.dirname(os.path.abspath(__file__))
if script_dir not in sys.path:
    sys.path.insert(0, script_dir)

import idaapi
import ida_kernwin
import ida_auto
from core.engine import PwnDetectionEngine
from core.fixer import AutoFixEngine
from utils.logger import file_logger


class PwnVulnDetectorPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Auto detect common CTF PWN vulnerabilities."
    help = "Run the plugin to analyze all functions."
    wanted_name = "CTF PWN Vulnerability Detector"
    wanted_hotkey = "Ctrl-Alt-P"

    def init(self):
        try:
            if not idaapi.init_hexrays_plugin():
                file_logger.error("Hex-Rays is not available.")
                return idaapi.PLUGIN_SKIP
            file_logger.info(
                f"{self.wanted_name} initialized. Press {self.wanted_hotkey} to run."
            )
            return idaapi.PLUGIN_KEEP
        except Exception as exc:
            file_logger.error(f"Failed to initialize plugin: {exc}")
            return idaapi.PLUGIN_SKIP

    def run(self, arg):
        file_logger.info(f"{self.wanted_name} scan started.")

        try:
            from utils.ui_helper import clear_all_highlights, show_vulnerabilities

            clear_all_highlights()
            findings = PwnDetectionEngine().analyze_program()
            findings = self._maybe_apply_auto_fix(findings)

            clear_all_highlights()
            file_logger.info(
                f"{self.wanted_name} scan finished. Found {len(findings)} finding(s)."
            )

            if findings:
                show_vulnerabilities(findings)
            else:
                file_logger.info("No candidate vulnerabilities were detected.")
        except Exception as exc:
            file_logger.error(f"Plugin run failed: {exc}")

    def _maybe_apply_auto_fix(self, findings):
        if not findings:
            return findings

        fixer = AutoFixEngine()
        candidates = fixer.collect_candidates(findings)
        auto_ready = [item for item in candidates if item.patchable]
        if not auto_ready:
            return findings

        answer = ida_kernwin.ask_yn(
            ida_kernwin.ASKBTN_NO,
            (
                f"[{self.wanted_name}] {len(auto_ready)} auto-fix action(s) are ready.\n"
                "Apply patchable fixes now?"
            ),
        )
        if answer != ida_kernwin.ASKBTN_YES:
            return findings

        result = fixer.apply_all(findings)
        for line in result.failed:
            file_logger.warning(f"Auto-fix failed: {line}")
        for line in result.skipped:
            file_logger.debug(f"Auto-fix skipped: {line}")

        if result.applied_count == 0:
            file_logger.info("Auto-fix applied 0 patch(es).")
            return findings

        file_logger.info(f"Auto-fix applied {result.applied_count} patch(es).")
        ida_auto.auto_wait()
        file_logger.info("Re-scanning after auto-fix patches.")
        return PwnDetectionEngine().analyze_program()

    def term(self):
        try:
            from utils.ui_helper import clear_all_highlights

            clear_all_highlights()
        except Exception as exc:
            file_logger.error(f"Error during plugin termination: {exc}")
        file_logger.info(f"{self.wanted_name} terminated.")

def PLUGIN_ENTRY():
    return PwnVulnDetectorPlugin()

if __name__ == "__main__":
    plugin = PwnVulnDetectorPlugin()
    if plugin.init() == idaapi.PLUGIN_KEEP:
        plugin.run(0)
        plugin.term()
