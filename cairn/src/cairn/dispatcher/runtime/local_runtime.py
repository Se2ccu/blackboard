"""Local execution backend for Cairn Dispatcher.

Replaces the Docker-based ``ContainerManager`` + ``ManagedProcess`` with a
local-subprocess implementation, so the dispatcher can run worker commands on
the host machine without Docker.

It implements the same surface that ``tasks/*.py`` and ``runtime/*`` modules
rely on:

- ``container_name(project_id)``  -> logical name string
- ``ensure_running(project_id)``  -> no-op, returns the name (no container)
- ``create_startup_container()``   -> returns a fixed logical name
- ``build_exec_process(...)``      -> :class:`LocalManagedProcess`
- ``write_text_file(...)``         -> writes to the real host filesystem
- ``remove_container`` / ``cleanup_*`` / ``needs_*_cleanup`` / ``inspect_state`` -> no-ops/stubs
- ``close()``                     -> nothing to close

The returned process objects are duck-typed to match
:class:`cairn.dispatcher.runtime.process.ManagedProcess`
(``start`` / ``communicate`` / ``kill`` / ``cancel``), so callers do not change.
"""

from __future__ import annotations

import logging
import os
import shlex
import signal
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any

from cairn.dispatcher.config import ContainerConfig
from cairn.dispatcher.runtime.process import ProcessResult

LOG = logging.getLogger(__name__)

# Mirrors tasks/common.py GRAPH_SNAPSHOT_ROOT so local workers can read the
# same snapshot paths. Kept here to avoid an import cycle with tasks.common.
GRAPH_SNAPSHOT_ROOT = "/tmp/cairn-prompts"

# Logical name for the single "container" the local backend pretends to use.
_LOCAL_CONTAINER_NAME = "cairn-local"


class LocalManagedProcess:
    """Runs a command on the host via :mod:`subprocess`.

    Mirrors the interface of :class:`ManagedProcess`:

    - ``start()`` spawns the process (wrapped in ``timeout`` for the kill
      deadline, mirroring the docker-exec path).
    - ``communicate(timeout=...)`` joins the reader threads, returns a
      :class:`ProcessResult`.
    - ``kill()`` / ``cancel(reason)`` terminate the process group.
    """

    def __init__(self, command: list[str], env: dict[str, str], timeout_seconds: int | None, tee_path: str | None = None):
        self.command = command
        self.env = env
        self._timeout_seconds = timeout_seconds
        self._proc: subprocess.Popen[bytes] | None = None
        self._stdout: list[bytes] = []
        self._stderr: list[bytes] = []
        self._returncode: int | None = None
        self._timed_out = False
        self._cancel_reason: str | None = None
        self._read_error: str | None = None
        self._done = threading.Event()
        self._reader_out: threading.Thread | None = None
        self._reader_err: threading.Thread | None = None
        self._tee_path = tee_path
        self._started_at: str | None = None
        self._live_path: Path | None = self._compute_live_path()

    def _compute_live_path(self) -> Path | None:
        """For opencode, write stdout to a live jsonl so --live can tail it."""
        if not self._tee_path or not self.command or self.command[0] != "opencode":
            return None
        return Path(self._tee_path).parent / "sessions" / "live.jsonl"

    def start(self) -> None:
        # Build argv. We wrap with `timeout -k` when a timeout is set, exactly
        # like ContainerManager.build_exec_process does for docker exec.
        argv: list[str] = []
        if self._timeout_seconds is not None:
            argv.extend(["timeout", "-k", "5s", f"{self._timeout_seconds}s"])
        argv.extend(self.command)

        # Merge worker env over the current process env so the command sees
        # MOCK_* / API keys etc.
        run_env = dict(os.environ)
        run_env.update({k: str(v) for k, v in self.env.items()})

        LOG.debug("local exec: %s", shlex.join(argv))
        self._started_at = datetime.now().isoformat(timespec="seconds")
        self._proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=run_env,
            start_new_session=True,  # new process group so we can kill the tree
        )
        self._reader_out = threading.Thread(target=self._read_stream, args=(self._proc.stdout, self._stdout), daemon=True)
        self._reader_err = threading.Thread(target=self._read_stream, args=(self._proc.stderr, self._stderr), daemon=True)
        self._reader_out.start()
        self._reader_err.start()

    def communicate(self, timeout: float | None) -> ProcessResult:
        assert self._proc is not None
        # Reader threads finish when the pipe closes (process exits).
        if self._reader_out is not None:
            self._reader_out.join(timeout=timeout)
        if self._reader_out is not None and self._reader_out.is_alive():
            # Timed out waiting.
            self._timed_out = True
            self.kill()
            if self._reader_out is not None:
                self._reader_out.join(timeout=5.0)
            if self._reader_err is not None:
                self._reader_err.join(timeout=5.0)

        # If not timed out, ensure stderr reader is also joined.
        if not self._timed_out and self._reader_err is not None:
            self._reader_err.join(timeout=5.0)

        self._done.wait(timeout=0)
        if self._returncode is None:
            self._returncode = self._proc.returncode if self._proc.returncode is not None else 1
        if self._read_error and not self._stderr:
            self._stderr.append(self._read_error.encode("utf-8", errors="replace"))
        self._write_tee()
        return ProcessResult(
            returncode=self._returncode,
            stdout=b"".join(self._stdout).decode("utf-8", errors="replace"),
            stderr=b"".join(self._stderr).decode("utf-8", errors="replace"),
            timed_out=self._timed_out,
            cancelled=self._cancel_reason is not None,
            cancel_reason=self._cancel_reason,
        )

    def kill(self) -> None:
        if self._proc is None or self._proc.returncode is not None:
            return
        try:
            os.killpg(os.getpgid(self._proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        except Exception as exc:  # noqa: BLE001
            LOG.warning("local kill failed pid=%s error=%s", self._proc.pid, exc)

    def cancel(self, reason: str) -> None:
        if self._cancel_reason is None:
            self._cancel_reason = reason
        self.kill()

    def _write_tee(self) -> None:
        # Dump the full captured stdout/stderr to a session log so the worker's
        # raw process I/O survives after extract_response_text consumes it.
        # Complements `claude -r <session> --resume` (see header) which holds the
        # full step-by-step reasoning; this file holds the process-level I/O.
        if not self._tee_path:
            return
        try:
            Path(self._tee_path).parent.mkdir(parents=True, exist_ok=True)
            stdout_text = b"".join(self._stdout).decode("utf-8", errors="replace")
            stderr_text = b"".join(self._stderr).decode("utf-8", errors="replace")
            session_id = self._extract_session_id(self.command)
            lines = [
                "=== cairn local worker session ===",
                f"started: {self._started_at}",
                f"command: {shlex.join(self.command)[:500]}",
            ]
            if session_id:
                resume_hint = self._resume_hint(session_id)
                if resume_hint:
                    lines.append(f"session_id: {session_id}  (resume full reasoning: {resume_hint})")
            lines.extend(["--- stdout ---", stdout_text or "(empty)"])
            lines.extend(["--- stderr ---", stderr_text or "(empty)"])
            lines.append(
                f"--- exit: code={self._returncode} timed_out={self._timed_out} "
                f"cancelled={self._cancel_reason is not None} ---"
            )
            Path(self._tee_path).write_text("\n".join(lines) + "\n", encoding="utf-8")
            self._copy_trace(session_id, stdout_text)
            # Remove the live file after the final trace is archived
            if self._live_path is not None and self._live_path.exists():
                try:
                    self._live_path.unlink()
                except Exception:  # noqa: BLE001
                    pass
        except Exception as exc:  # noqa: BLE001
            LOG.warning("tee write failed path=%s error=%s", self._tee_path, exc)

    def _copy_trace(self, session_id: str | None, stdout_text: str) -> None:
        """Copy the full reasoning trace next to the session log."""
        if not session_id:
            return
        # claude stores full reasoning in ~/.claude/projects/<cwd-dashes>/<id>.jsonl
        # opencode stores full reasoning in stdout (JSON event stream)
        if self.command and self.command[0] == "claude":
            self._copy_claude_trace(session_id)
        elif self.command and self.command[0] == "opencode":
            self._copy_opencode_trace(session_id, stdout_text)

    def _copy_opencode_trace(self, session_id: str, stdout_text: str) -> None:
        """opencode emits full reasoning as JSON events on stdout.
        Save the raw JSONL alongside the session log for traceability."""
        if not stdout_text.strip():
            return
        dst = Path(self._tee_path).parent / "sessions" / f"{session_id}.jsonl"
        try:
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_text(stdout_text, encoding="utf-8")
            self._render_trace_md(dst)
        except Exception as exc:  # noqa: BLE001
            LOG.warning("opencode trace copy failed error=%s", exc)

    @staticmethod
    def _resume_hint(session_id: str) -> str | None:
        """Return a CLI resume hint string for the session, or None."""
        return f"opencode run -s {session_id} --auto --format json"

    def _copy_claude_trace(self, session_id: str | None) -> None:
        # The real step-by-step reasoning (thinking / tool_use / tool_result) lives
        # in claude's own session jsonl under ~/.claude/projects/<cwd-as-dashes>/.
        # Copy it next to the session.log so the full reasoning trace travels with
        # the project artifacts and lines up with the Fact it produced. session.log
        # only captured process-level stdout (usually empty for `claude -p`); this
        # jsonl is where the actual intermediate process is.
        if not session_id:
            return
        import os
        cwd = os.getcwd()
        project_dir = "~/.claude/projects/" + cwd.replace("/", "-")
        src = Path(os.path.expanduser(project_dir)).joinpath(f"{session_id}.jsonl")
        if not src.is_file():
            return
        dst = Path(self._tee_path).parent / "sessions" / f"{session_id}.jsonl"
        try:
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(src.read_bytes())
            # Auto-render a human-readable markdown alongside the jsonl, so you
            # never have to hand-run render_session.py for archived sessions.
            # --live is still manual for realtime watching while the worker runs.
            self._render_trace_md(dst)
        except Exception as exc:  # noqa: BLE001
            LOG.warning("claude trace copy failed src=%s error=%s", src, exc)

    @staticmethod
    def _render_trace_md(jsonl_path: Path) -> None:
        import os
        import subprocess
        md_path = jsonl_path.with_suffix(".md")
        # render_session.py lives at the repo root (dispatcher cwd), not under runs/.
        renderer = Path(os.getcwd()) / "tools" / "render_session.py"
        if not renderer.is_file():
            return
        try:
            subprocess.run(
                [sys.executable, str(renderer), str(jsonl_path), "--out", str(md_path)],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=30,
                cwd=os.getcwd(),
            )
        except Exception as exc:  # noqa: BLE001
            LOG.warning("trace md render failed jsonl=%s error=%s", jsonl_path, exc)

    @staticmethod
    def _extract_session_id(command: list[str]) -> str | None:
        for index, arg in enumerate(command):
            # claude: --session-id <id> or -r <id>
            if arg == "--session-id" and index + 1 < len(command):
                return command[index + 1]
            if arg == "-r" and index > 0 and command[0] == "claude" and index + 1 < len(command):
                return command[index + 1]
            # opencode: -s <id>
            if arg == "-s" and index > 0 and command[0] == "opencode" and index + 1 < len(command):
                return command[index + 1]
        return None

    def _read_stream(self, pipe: Any, sink: list[bytes]) -> None:
        is_stdout = pipe is self._proc.stdout if self._proc else False
        live_file = None
        if is_stdout and self._live_path is not None:
            try:
                self._live_path.parent.mkdir(parents=True, exist_ok=True)
                live_file = self._live_path.open("ab", buffering=0)
            except Exception as exc:  # noqa: BLE001
                LOG.warning("live file open failed path=%s error=%s", self._live_path, exc)
        try:
            assert pipe is not None
            while True:
                chunk = pipe.read(4096)
                if not chunk:
                    break
                sink.append(chunk)
                if live_file is not None:
                    try:
                        live_file.write(chunk)
                    except Exception:  # noqa: BLE001
                        pass
        except Exception as exc:  # noqa: BLE001
            self._read_error = str(exc)
        finally:
            if live_file is not None:
                try:
                    live_file.close()
                except Exception:  # noqa: BLE001
                    pass
            try:
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
            except Exception:  # noqa: BLE001
                pass
            self._returncode = self._proc.returncode if self._proc is not None else 1
            self._done.set()


class LocalContainerManager:
    """Drop-in replacement for :class:`ContainerManager` that runs on the host.

    The "container" is purely logical: each project maps to a name string, and
    commands run directly on the host via :class:`LocalManagedProcess`. This
    exists so the dispatcher works without Docker (e.g. for local mock runs
    against a host-resident target like a vulnerable UDP service).
    """

    _PREFIX = "cairn-local-"

    def __init__(self, config: ContainerConfig):
        self._config = config

    def close(self) -> None:
        # Nothing to close (no docker client).
        return

    def container_name(self, project_id: str) -> str:
        sanitized = project_id.replace("/", "-")
        return f"{self._PREFIX}{sanitized}"

    def _tee_path(self, container_name: str) -> str:
        # Per-process session log under runs/<project_id>/. Relative to the
        # dispatcher cwd (repo root), so it lands next to the agent's own
        # spill-to-disk artifacts.
        if container_name.startswith(self._PREFIX):
            project_id = container_name[len(self._PREFIX):]
        else:
            project_id = container_name
        return str(Path("runs").resolve() / project_id / f"session-{uuid.uuid4().hex[:8]}.log")

    def ensure_running(self, project_id: str) -> str:
        # Local backend: no container to start. Return the logical name.
        name = self.container_name(project_id)
        LOG.debug("local ensure_running project=%s name=%s (no-op)", project_id, name)
        return name

    def create_startup_container(self) -> str:
        # No real container; return a fixed logical name.
        LOG.debug("local create_startup_container -> %s (no-op)", _LOCAL_CONTAINER_NAME)
        return _LOCAL_CONTAINER_NAME

    def inspect_state(self, name: str) -> str | None:
        # No container state to inspect. Returning None means "does not exist",
        # which makes needs_*_cleanup() return False (nothing to clean).
        return None

    def build_exec_process(
        self,
        container_name: str,
        env: dict[str, str],
        command: list[str],
        timeout_seconds: int | None = None,
        kill_after_seconds: int = 5,
    ) -> LocalManagedProcess:
        return LocalManagedProcess(
            command=command,
            env=env,
            timeout_seconds=timeout_seconds,
            tee_path=self._tee_path(container_name),
        )

    def write_text_file(self, container_name: str, path: str, content: str) -> None:
        # Write to the real host filesystem so local worker processes can read
        # the graph snapshot via the same path they'd use in a container.
        target = PurePosixPath(path)
        if not target.is_absolute():
            raise ValueError(f"container file path must be absolute: {path}")
        local_path = Path(path)
        local_path.parent.mkdir(parents=True, exist_ok=True)
        local_path.write_text(content, encoding="utf-8")
        LOG.debug("local write_text_file container=%s path=%s bytes=%s", container_name, path, len(content))

    def cleanup_completed(self, project_id: str) -> bool:
        # Nothing to clean locally.
        return True

    def cleanup_stopped(self, project_id: str) -> bool:
        return True

    def cleanup_orphan(self, name: str) -> bool:
        return True

    def managed_container_names(self) -> list[str]:
        return []

    def needs_completed_cleanup(self, project_id: str) -> bool:
        return False

    def needs_orphan_cleanup(self, name: str) -> bool:
        return False

    def needs_stopped_cleanup(self, project_id: str) -> bool:
        return False

    def remove_container(self, name: str, *, force: bool = True) -> None:
        return
