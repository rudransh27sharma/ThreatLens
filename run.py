"""Single-command launcher for PhishGuard.

Starts the FastAPI backend and the Streamlit frontend as two child processes,
streams their output with a [backend] / [frontend] prefix, and shuts both down
cleanly on Ctrl-C or when either process exits unexpectedly.

Usage:
    python run.py

Both processes use the same Python interpreter that runs this script, so no
virtual-environment activation is needed as long as you call:

    .venv\\bin\\python run.py          # macOS / Linux
    .venv\\bin\\python.exe run.py      # Windows (MSYS2 / Git-bash)
    .venv\\Scripts\\python.exe run.py  # Windows (cmd / PowerShell)
"""

from __future__ import annotations

import os
import signal
import socket
import subprocess
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# Always use the venv interpreter bundled with this project so the right
# packages are found regardless of which `python` is on PATH.
_VENV_WIN = ROOT / ".venv" / "Scripts" / "python.exe"
_VENV_UNIX = ROOT / ".venv" / "bin" / "python"
PYTHON = (
    str(_VENV_WIN) if _VENV_WIN.exists()
    else str(_VENV_UNIX) if _VENV_UNIX.exists()
    else sys.executable  # fallback: hope the active env has everything
)

BACKEND_CMD = [
    PYTHON, "-m", "uvicorn",
    "backend.main:app",
    "--host", "127.0.0.1",
    "--port", "8000",
    "--reload",
]

FRONTEND_CMD = [
    PYTHON, "-m", "streamlit", "run",
    str(ROOT / "frontend" / "app.py"),
    "--server.port", "8501",
    "--server.headless", "true",
]


def _stream(proc: subprocess.Popen, label: str) -> None:
    """Read lines from *proc* stdout and print them with a prefix label."""
    assert proc.stdout is not None
    for raw in proc.stdout:
        try:
            line = raw.decode("utf-8", errors="replace").rstrip()
        except Exception:
            line = repr(raw)
        print(f"[{label}] {line}", flush=True)


def _port_in_use(port: int) -> bool:
    """Return True if something is already listening on *port*."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.3)
        return s.connect_ex(("127.0.0.1", port)) == 0


def _free_port(port: int, label: str) -> None:
    """Kill every process listening on *port* before we try to bind it.

    Works on Windows (taskkill) and Unix (kill).  Silently skips PIDs that
    have already exited by the time we try to kill them.
    """
    if not _port_in_use(port):
        return

    print(f"  Port {port} is already in use — clearing it for {label}…")

    if sys.platform == "win32":
        # netstat output: "  TCP  0.0.0.0:8000  ...  LISTENING  1234"
        try:
            out = subprocess.check_output(
                ["netstat", "-ano"],
                stderr=subprocess.DEVNULL,
                text=True,
            )
        except Exception:
            out = ""
        pids: set[int] = set()
        for line in out.splitlines():
            if f":{port}" in line and "LISTENING" in line:
                parts = line.strip().split()
                try:
                    pids.add(int(parts[-1]))
                except (ValueError, IndexError):
                    pass
        for pid in pids:
            try:
                subprocess.call(
                    ["taskkill", "/PID", str(pid), "/F"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                print(f"  Killed PID {pid} (was on port {port})")
            except Exception:
                pass
    else:
        # Unix: use lsof or fuser
        for cmd in [["fuser", "-k", f"{port}/tcp"], ["lsof", "-ti", f":{port}"]]:
            try:
                out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
                for pid_str in out.split():
                    try:
                        os.kill(int(pid_str), signal.SIGTERM)
                        print(f"  Killed PID {pid_str} (was on port {port})")
                    except (ProcessLookupError, ValueError):
                        pass
                break
            except (subprocess.CalledProcessError, FileNotFoundError):
                continue


def main() -> None:
    print("Starting PhishGuard...")

    # Clear ports before binding — prevents "address already in use" crashes
    # that happen when a previous run didn't shut down cleanly.
    _free_port(8000, "backend")
    _free_port(8501, "frontend")

    print(f"  Backend  → http://127.0.0.1:8000")
    print(f"  Frontend → http://localhost:8501")
    print("Press Ctrl-C to stop both servers.\n")

    backend = subprocess.Popen(
        BACKEND_CMD,
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    frontend = subprocess.Popen(
        FRONTEND_CMD,
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    threading.Thread(target=_stream, args=(backend, "backend"), daemon=True).start()
    threading.Thread(target=_stream, args=(frontend, "frontend"), daemon=True).start()

    try:
        # Block until either process exits on its own (error / crash).
        while True:
            rc_b = backend.poll()
            rc_f = frontend.poll()
            if rc_b is not None:
                print(f"\n[backend] exited with code {rc_b}. Stopping frontend.")
                frontend.terminate()
                break
            if rc_f is not None:
                print(f"\n[frontend] exited with code {rc_f}. Stopping backend.")
                backend.terminate()
                break
            threading.Event().wait(0.5)
    except KeyboardInterrupt:
        print("\nShutting down...")
        backend.terminate()
        frontend.terminate()
    finally:
        backend.wait()
        frontend.wait()
        print("Both servers stopped.")


if __name__ == "__main__":
    main()
