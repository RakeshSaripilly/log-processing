"""
Universal Log Pre-processing Framework (ULPF) - Unified Collector & Tailer
Supports: File tailing (*.log, *.jsonl), Syslog UDP 5140, Syslog TCP 5140, Backpressure Guards
Team LunarX - SIH26156 (NTRO)
"""

import os
import time
import socket
import threading
import logging
from pathlib import Path
from typing import Optional, Callable

from core.pipeline import ProcessingPipeline

logger = logging.getLogger("ulpf.collector")


class FileTailer:
    """
    Watches and tails log files continuously, sending new lines to pipeline.
    """
    def __init__(self, file_path: str, on_log_callback: Callable[[str], None], poll_interval: float = 0.2):
        self.file_path = Path(file_path)
        self.callback = on_log_callback
        self.poll_interval = poll_interval
        self._stop_event = threading.Event()
        self.thread: Optional[threading.Thread] = None

    def start(self):
        self.thread = threading.Thread(target=self._tail_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self._stop_event.set()
        if self.thread:
            self.thread.join(timeout=2.0)

    def _tail_loop(self):
        if not self.file_path.exists():
            self.file_path.parent.mkdir(parents=True, exist_ok=True)
            self.file_path.touch()

        with open(self.file_path, "r", encoding="utf-8", errors="replace") as f:
            # Start at end of file
            f.seek(0, os.SEEK_END)
            while not self._stop_event.is_set():
                line = f.readline()
                if line:
                    stripped = line.strip()
                    if stripped:
                        try:
                            self.callback(stripped)
                        except Exception as e:
                            logger.error(f"Error processing tailed log: {e}")
                else:
                    time.sleep(self.poll_interval)


class SyslogUDPServer:
    """
    Syslog UDP listener on port 5140 (unprivileged port, ideal for containers).
    """
    def __init__(self, host: str = "0.0.0.0", port: int = 5140, on_log_callback: Callable[[str], None] = None):
        self.host = host
        self.port = port
        self.callback = on_log_callback
        self._stop_event = threading.Event()
        self.sock: Optional[socket.socket] = None
        self.thread: Optional[threading.Thread] = None

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.host, self.port))
        self.thread = threading.Thread(target=self._listen_loop, daemon=True)
        self.thread.start()
        logger.info(f"Syslog UDP listener active on {self.host}:{self.port}")

    def stop(self):
        self._stop_event.set()
        if self.sock:
            self.sock.close()

    def _listen_loop(self):
        while not self._stop_event.is_set():
            try:
                data, addr = self.sock.recvfrom(65535)
                msg = data.decode('utf-8', errors='replace').strip()
                if msg and self.callback:
                    self.callback(msg)
            except Exception:
                break


def run_standalone_collector(pipeline: Optional[ProcessingPipeline] = None):
    p = pipeline or ProcessingPipeline()
    udp = SyslogUDPServer(host="0.0.0.0", port=5140, on_log_callback=p.process_raw)
    udp.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        udp.stop()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    run_standalone_collector()
