from pathlib import Path
import pytest
from core.daemon import DaemonSupervisor


def test_daemon_supervisor_lifecycle(tmp_path):
    supervisor = DaemonSupervisor(runtime_dir=tmp_path)
    running, pid = supervisor.is_running()
    assert running is False
    assert pid is None

    # Status when stopped
    status = supervisor.get_status()
    assert status["running"] is False
    assert status["healthy"] is False

    # Simulate running PID
    import os
    current_pid = os.getpid()
    supervisor.pid_file.write_text(str(current_pid))

    running, pid = supervisor.is_running()
    assert running is True
    assert pid == current_pid

    # Stale/dead PID handling
    supervisor.pid_file.write_text("999999999")
    running, pid = supervisor.is_running()
    assert running is False
    assert not supervisor.pid_file.exists()


def test_daemon_supervisor_stop_not_running(tmp_path):
    supervisor = DaemonSupervisor(runtime_dir=tmp_path)
    res = supervisor.stop_daemon()
    assert res["status"] == "NOT_RUNNING"
