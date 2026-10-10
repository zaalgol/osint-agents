"""Tor for the anonymous network profile: start/stop/check a local Tor client.

Uses the official Tor Expert Bundle (verify its GPG signature before first use). Tor
runs as a detached background process with a generated torrc: SOCKS on 127.0.0.1 only,
client-only, state in %LOCALAPPDATA%/osint-tor/state.

Circuit isolation: each investigation connects with its own SOCKS username, and Tor
(IsolateSOCKSAuth, on by default) keeps different credentials on different circuits.
Exit relays can't link activity across investigations.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import httpx

CHECK_URL = "https://check.torproject.org/api/ip"


@dataclass
class TorStatus:
    running: bool
    bootstrapped: int
    is_tor: bool | None = None
    exit_ip: str | None = None
    detail: str = ""


def _state_dir(settings) -> Path:
    return Path(os.path.expandvars(settings.tor.data_dir))


def _pid_file(settings) -> Path:
    return _state_dir(settings) / "tor.pid"


def _log_file(settings) -> Path:
    return _state_dir(settings) / "tor.log"


def socks_url(settings, investigation_id: int | None = None) -> str:
    """SOCKS URL for an investigation: own credentials = own circuits."""
    user = f"inv{investigation_id}" if investigation_id is not None else "osint"
    return f"socks5://{user}:x@127.0.0.1:{settings.tor.socks_port}"


def browser_socks_url(settings) -> str:
    """Chromium can't send SOCKS credentials: its own port, one circuit per destination."""
    return f"socks5://127.0.0.1:{settings.tor.browser_socks_port}"


def _alive(pid: int) -> bool:
    if sys.platform == "win32":
        out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH"], capture_output=True,
                             text=True, check=False).stdout
        return str(pid) in out and "tor.exe" in out.lower()
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _bootstrap(settings) -> int:
    log = _log_file(settings)
    if not log.exists():
        return 0
    pct = 0
    for line in log.read_text(encoding="utf-8", errors="replace").splitlines()[-200:]:
        if "Bootstrapped " in line:
            try:
                pct = int(line.split("Bootstrapped ")[1].split("%")[0])
            except ValueError:
                pass
    return pct


def _port_open(port: int) -> bool:
    import socket

    with socket.socket() as sock:
        sock.settimeout(2)
        return sock.connect_ex(("127.0.0.1", port)) == 0


def check_exit(settings, investigation_id: int | None = None, timeout: float = 30) -> TorStatus:
    """Ask check.torproject.org, through Tor, whether traffic really exits via Tor."""
    try:
        with httpx.Client(proxy=socks_url(settings, investigation_id), timeout=timeout) as c:
            data = c.get(CHECK_URL).json()
        return TorStatus(True, 100, bool(data.get("IsTor")), data.get("IP"))
    except Exception as e:  # noqa: BLE001 - any failure = not usable
        return TorStatus(False, _bootstrap(settings), detail=f"{type(e).__name__}: {e}"[:200])


def status(settings) -> TorStatus:
    pid_file = _pid_file(settings)
    pid = int(pid_file.read_text()) if pid_file.exists() else None
    running = bool(pid and _alive(pid))
    st = check_exit(settings) if running else TorStatus(False, 0, detail="not running")
    st.running = running
    st.bootstrapped = _bootstrap(settings) if running else 0
    return st


def start(settings, wait_s: float = 120) -> TorStatus:
    tor = Path(os.path.expandvars(settings.tor.binary))
    if not tor.exists():
        raise RuntimeError(f"tor not found at {tor}; install the Tor Expert Bundle (see README)")
    cur = status(settings)
    if cur.running and cur.is_tor and _port_open(settings.tor.browser_socks_port):
        return cur
    if cur.running:
        stop(settings)
    state = _state_dir(settings)
    (state / "data").mkdir(parents=True, exist_ok=True)
    log = _log_file(settings)
    if log.exists():
        log.unlink()
    geo = tor.parent.parent / "data"
    torrc = state / "torrc"
    torrc.write_text("\n".join([
        f"SocksPort 127.0.0.1:{settings.tor.socks_port} IsolateSOCKSAuth",
        f"SocksPort 127.0.0.1:{settings.tor.browser_socks_port} IsolateDestAddr",
        f"DataDirectory {(state / 'data').as_posix()}",
        f"Log notice file {log.as_posix()}",
        "ClientOnly 1",
        "AvoidDiskWrites 1",
        f"GeoIPFile {(geo / 'geoip').as_posix()}",
        f"GeoIPv6File {(geo / 'geoip6').as_posix()}",
    ]) + "\n", encoding="utf-8")
    flags = 0
    if sys.platform == "win32":
        flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    proc = subprocess.Popen([str(tor), "-f", str(torrc)], stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
                            creationflags=flags, close_fds=True)
    _pid_file(settings).write_text(str(proc.pid))
    deadline = time.monotonic() + wait_s
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"tor exited (code {proc.returncode}); see {log}")
        if _bootstrap(settings) >= 100:
            break
        time.sleep(2)
    st = check_exit(settings)
    st.running = proc.poll() is None
    st.bootstrapped = _bootstrap(settings)
    return st


def stop(settings) -> bool:
    pid_file = _pid_file(settings)
    if not pid_file.exists():
        return False
    pid = int(pid_file.read_text())
    if _alive(pid):
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True, check=False)
        else:
            os.kill(pid, 15)
    pid_file.unlink(missing_ok=True)
    return True


class TorUnavailable(RuntimeError):
    """Anonymous profile without a working Tor: refuse to run (fail closed)."""


def ensure(settings, investigation_id: int | None = None) -> TorStatus:
    st = check_exit(settings, investigation_id)
    if st.is_tor:
        return st
    if settings.tor.auto_start:
        st = start(settings)
        st = check_exit(settings, investigation_id)
        if st.is_tor:
            return st
    raise TorUnavailable("Tor is not available, so this anonymous investigation won't run "
                         f"(it never falls back to a direct connection). {st.detail}")
