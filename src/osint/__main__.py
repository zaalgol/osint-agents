import os
import signal
import sys
import threading
import time
from pathlib import Path

from osint.cli import app

if sys.platform == "win32":
    # Ctrl+Break pauses like Ctrl+C: tasks go back to the queue
    signal.signal(signal.SIGBREAK, signal.default_int_handler)

if stop_file := os.environ.get("OSINT_STOP_FILE"):
    # The web GUI cancels a job by creating this file. Console signals can't reach a
    # process started without a console, so the process interrupts itself: the same
    # graceful pause as Ctrl+C (in-flight tasks are released back to the queue).
    def _watch(path: Path) -> None:
        while not path.exists():
            time.sleep(1)
        signal.raise_signal(signal.SIGINT)

    threading.Thread(target=_watch, args=(Path(stop_file),), daemon=True).start()

app(prog_name="osint")
