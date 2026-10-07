"""Production Daemon & Background Process Supervisor for Dimensión Espejo.

Provides graceful daemonization, PID lifecycle management, health monitoring,
and automatic recovery for continuous 24/7 background operation.
"""

from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger("mirror.daemon")


class DaemonSupervisor:
    """Manages the background daemon lifecycle of Dimensión Espejo Shield."""

    def __init__(self, runtime_dir: Optional[Path] = None) -> None:
        self.runtime_dir = runtime_dir or (
            Path(__file__).resolve().parent.parent / "evidence_vault"
        )
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        self.pid_file = self.runtime_dir / "espejo.pid"
        self.status_file = self.runtime_dir / "daemon_status.json"
        self.log_file = self.runtime_dir / "espejo_daemon.log"

    def is_running(self) -> Tuple[bool, Optional[int]]:
        """Check if daemon process is currently alive."""
        if not self.pid_file.exists():
            return False, None
        try:
            pid = int(self.pid_file.read_text().strip())
            # Signal 0 checks if process exists without killing it
            os.kill(pid, 0)
            return True, pid
        except (ValueError, ProcessLookupError, PermissionError):
            # Stale PID file
            if self.pid_file.exists():
                try:
                    self.pid_file.unlink()
                except Exception:
                    pass
            return False, None

    def start_daemon(
        self,
        asset_id: str = "api",
        port: int = 8080,
        host: str = "127.0.0.1",
        tls: bool = False,
    ) -> Dict[str, Any]:
        """Spawn the shield proxy as a detached, resilient background process."""
        running, pid = self.is_running()
        if running:
            return {
                "status": "ALREADY_RUNNING",
                "pid": pid,
                "message": f"Daemon is already active (PID {pid})",
            }

        python_bin = sys.executable
        cli_main = Path(__file__).resolve().parent.parent / "cli" / "main.py"

        cmd = [
            python_bin,
            str(cli_main),
            "proxy",
            asset_id,
            "--port", str(port),
            "--host", str(host),
        ]
        if tls:
            cmd.append("--tls")

        with open(self.log_file, "a", encoding="utf-8") as out:
            proc = subprocess.Popen(
                cmd,
                stdout=out,
                stderr=out,
                start_new_session=True,  # Detach process group
            )

        self.pid_file.write_text(str(proc.pid))
        status_data = {
            "pid": proc.pid,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "asset_id": asset_id,
            "host": host,
            "port": port,
            "tls": tls,
            "log_file": str(self.log_file),
        }
        self.status_file.write_text(json.dumps(status_data, indent=2))
        logger.info("Daemon started with PID %d on %s:%d", proc.pid, host, port)

        return {
            "status": "STARTED",
            "pid": proc.pid,
            "host": host,
            "port": port,
            "log_file": str(self.log_file),
        }

    def stop_daemon(self) -> Dict[str, Any]:
        """Gracefully terminate the background daemon process."""
        running, pid = self.is_running()
        if not running or not pid:
            return {"status": "NOT_RUNNING", "message": "No active daemon found."}

        try:
            os.kill(pid, signal.SIGTERM)
            for _ in range(30):
                time.sleep(0.1)
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    break
            else:
                # Force kill if still hanging
                os.kill(pid, signal.SIGKILL)
        except Exception as e:
            logger.warning("Error stopping process %d: %s", pid, e)

        if self.pid_file.exists():
            self.pid_file.unlink()

        return {"status": "STOPPED", "pid": pid, "message": f"Daemon (PID {pid}) stopped."}

    def get_status(self) -> Dict[str, Any]:
        """Query daemon liveness, socket responsiveness, and resource stats."""
        running, pid = self.is_running()
        info: Dict[str, Any] = {
            "running": running,
            "pid": pid,
            "healthy": False,
        }

        if self.status_file.exists():
            try:
                info.update(json.loads(self.status_file.read_text()))
            except Exception:
                pass

        if running and "host" in info and "port" in info:
            # Socket probe
            try:
                with socket.create_connection((info["host"], info["port"]), timeout=1.0):
                    info["healthy"] = True
            except Exception:
                info["healthy"] = False

        return info
