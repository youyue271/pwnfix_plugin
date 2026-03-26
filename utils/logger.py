import os
from datetime import datetime
from threading import Lock


class FileLogger:
    def __init__(self):
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        self.log_file = os.path.join(project_root, "detector.log")
        self._lock = Lock()
        self._start_session()

    def _start_session(self):
        try:
            with self._lock:
                with open(self.log_file, "w", encoding="utf-8") as handle:
                    handle.write(
                        "=== PwnVulnDetector session started at "
                        f"{datetime.now().isoformat(timespec='seconds')} ===\n"
                    )
        except Exception as exc:
            print(f"[LOGGER] failed to initialize log file: {exc}")

    def info(self, msg):
        self._write("INFO", msg, echo=True)

    def debug(self, msg):
        self._write("DEBUG", msg, echo=False)

    def warning(self, msg):
        self._write("WARN", msg, echo=True)

    def error(self, msg):
        self._write("ERROR", msg, echo=True)

    def _write(self, level, msg, echo):
        line = f"[{level}] {msg}"
        try:
            with self._lock:
                with open(self.log_file, "a", encoding="utf-8") as handle:
                    handle.write(line + "\n")
        except Exception:
            pass

        if echo:
            print(line)


file_logger = FileLogger()
