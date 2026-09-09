# SPDX-License-Identifier: AGPL-3.0-only
"""Policy-free bounded literal-argv process execution."""

from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
import math
from typing import Mapping, Sequence


DEFAULT_MAX_OUTPUT_BYTES = 64 * 1024
DEFAULT_MAX_STDIN_BYTES = 64 * 1024
DEFAULT_TIMEOUT_SECONDS = 30.0


class ProcessResult:
    def __init__(self, state: str, exit_code: int | None, signal: int | None,
                 duration_ms: int, stdout: str, stderr: str,
                 stdout_total_bytes: int, stderr_total_bytes: int,
                 stdout_omitted_bytes: int, stderr_omitted_bytes: int,
                 stdout_truncated: bool, stderr_truncated: bool,
                 untrusted_content: bool = True,
                 uncertainty_facts: dict[str, str | None] | None = None) -> None:
        self.state = state
        self.exit_code = exit_code
        self.signal = signal
        self.duration_ms = duration_ms
        self.stdout = stdout
        self.stderr = stderr
        self.stdout_total_bytes = stdout_total_bytes
        self.stderr_total_bytes = stderr_total_bytes
        self.stdout_omitted_bytes = stdout_omitted_bytes
        self.stderr_omitted_bytes = stderr_omitted_bytes
        self.stdout_truncated = stdout_truncated
        self.stderr_truncated = stderr_truncated
        self.untrusted_content = untrusted_content
        self.uncertainty_facts = uncertainty_facts or {
            "stdout_read_error": None,
            "stderr_read_error": None,
            "stdin_delivery_error": None,
        }

    def as_dict(self) -> dict[str, object]:
        return {
            "state": self.state,
            "exit_code": self.exit_code,
            "signal": self.signal,
            "duration_ms": self.duration_ms,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "stdout_total_bytes": self.stdout_total_bytes,
            "stderr_total_bytes": self.stderr_total_bytes,
            "stdout_omitted_bytes": self.stdout_omitted_bytes,
            "stderr_omitted_bytes": self.stderr_omitted_bytes,
            "stdout_truncated": self.stdout_truncated,
            "stderr_truncated": self.stderr_truncated,
            "uncertainty_facts": dict(self.uncertainty_facts),
            "uncertain": self.state in {"timed_out", "signaled"} or any(self.uncertainty_facts.values()),
            "untrusted_content": self.untrusted_content,
        }


class _Capture:
    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.data = bytearray()
        self.total = 0

    def add(self, chunk: bytes) -> None:
        self.total += len(chunk)
        if len(self.data) < self.limit:
            self.data.extend(chunk[: self.limit - len(self.data)])

    def text(self) -> str:
        return bytes(self.data).decode("utf-8", errors="replace")


def _result(state: str, started: float, *, exit_code: int | None = None,
            signal_number: int | None = None, stdout: _Capture | None = None,
            stderr: _Capture | None = None,
            uncertainty_facts: dict[str, str | None] | None = None) -> ProcessResult:
    out = stdout or _Capture(0)
    err = stderr or _Capture(0)
    return ProcessResult(
        state, exit_code, signal_number,
        max(0, int((time.monotonic() - started) * 1000)),
        out.text(), err.text(), out.total, err.total,
        max(0, out.total - len(out.data)), max(0, err.total - len(err.data)),
        out.total > len(out.data), err.total > len(err.data),
        uncertainty_facts=uncertainty_facts,
    )


def _process_group_exists(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def run_argv(
    argv: Sequence[str], *, cwd: str | os.PathLike[str] | None = None,
    env: Mapping[str, str] | None = None, stdin: str | bytes | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    max_stdin_bytes: int = DEFAULT_MAX_STDIN_BYTES,
    pass_fds: Sequence[int] = (),
) -> dict[str, object]:
    """Run literal ``argv`` with bounded I/O and a killable process group.

    Production callers supply host-chosen literal executables.  The
    ``start_new_session`` process group contains ordinary descendants;
    children that deliberately call ``setsid`` remain a residual host
    limitation rather than a reason to add daemon or cgroup machinery here.
    """
    started = time.monotonic()
    if (not isinstance(argv, (list, tuple)) or not argv
            or any(not isinstance(item, str) or not item for item in argv)):
        return _result("rejected", started).as_dict()
    if (not isinstance(timeout_seconds, (int, float)) or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
            or timeout_seconds > 300 or not isinstance(max_output_bytes, int)
            or max_output_bytes < 0 or max_output_bytes > 16 * 1024 * 1024
            or not isinstance(max_stdin_bytes, int) or max_stdin_bytes < 0
            or max_stdin_bytes > 4 * 1024 * 1024):
        return _result("rejected", started).as_dict()
    input_bytes = stdin.encode("utf-8") if isinstance(stdin, str) else stdin
    if input_bytes is not None and (not isinstance(input_bytes, bytes)
                                    or len(input_bytes) > max_stdin_bytes):
        return _result("rejected", started).as_dict()

    stdout, stderr = _Capture(max_output_bytes), _Capture(max_output_bytes)
    try:
        process = subprocess.Popen(
            list(argv), cwd=cwd, env=dict(env) if env is not None else None,
            stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False,
            start_new_session=True, pass_fds=tuple(pass_fds), close_fds=True,
        )
    except (OSError, TypeError, ValueError):
        return _result("spawn_failed", started, stdout=stdout, stderr=stderr).as_dict()

    uncertainty: dict[str, str | None] = {
        "stdout_read_error": None, "stderr_read_error": None,
        "stdin_delivery_error": None,
    }

    def drain(pipe: object, capture: _Capture, fact: str) -> None:
        try:
            while True:
                chunk = pipe.read(65536)  # type: ignore[attr-defined]
                if not chunk:
                    return
                capture.add(chunk)
        except (OSError, ValueError) as exc:
            uncertainty[fact] = type(exc).__name__

    def write_input() -> None:
        if process.stdin is None or input_bytes is None:
            return
        try:
            process.stdin.write(input_bytes)
            process.stdin.close()
        except (BrokenPipeError, OSError, ValueError) as exc:
            uncertainty["stdin_delivery_error"] = type(exc).__name__
            try:
                process.stdin.close()
            except (OSError, ValueError):
                pass

    readers = [
        threading.Thread(target=drain, args=(process.stdout, stdout, "stdout_read_error"), daemon=True),
        threading.Thread(target=drain, args=(process.stderr, stderr, "stderr_read_error"), daemon=True),
    ]
    for reader in readers:
        reader.start()
    writer = threading.Thread(target=write_input, daemon=True)
    writer.start()
    deadline = started + float(timeout_seconds)
    leader_exited = False
    timed_out = False
    while True:
        if not leader_exited:
            try:
                process.wait(timeout=max(0.0, min(.02, deadline - time.monotonic())))
                leader_exited = True
            except subprocess.TimeoutExpired:
                pass
        if leader_exited and not any(thread.is_alive() for thread in readers) \
                and not _process_group_exists(process.pid):
            break
        if time.monotonic() >= deadline:
            timed_out = True
            break
    if timed_out:
        for number in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(process.pid, number)
            except OSError:
                pass
            if number == signal.SIGTERM:
                time.sleep(.05)
        try:
            process.wait(timeout=.05)
        except subprocess.TimeoutExpired:
            pass
    for thread in readers:
        thread.join(timeout=.1 if timed_out else .02)
    writer.join(timeout=.1 if timed_out else .02)
    for pipe in (process.stdout, process.stderr, process.stdin):
        if pipe is not None:
            try:
                pipe.close()
            except (OSError, ValueError):
                pass
    return _result(
        "timed_out" if timed_out else ("signaled" if process.returncode is not None
                                       and process.returncode < 0 else "exited"),
        started,
        exit_code=(None if timed_out or process.returncode is None or process.returncode < 0
                   else process.returncode),
        signal_number=(None if timed_out or process.returncode is None or process.returncode >= 0
                       else -process.returncode),
        stdout=stdout, stderr=stderr, uncertainty_facts=uncertainty,
    ).as_dict()


__all__ = ["ProcessResult", "run_argv"]
