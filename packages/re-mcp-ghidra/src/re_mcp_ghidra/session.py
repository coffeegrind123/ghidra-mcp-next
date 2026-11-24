# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Database session manager for Ghidra via pyghidra.

Tracks whether a program is currently open and provides guards
for tools that require an open database.
"""

from __future__ import annotations

import functools
import inspect
import logging
import os
import shutil
import signal
from collections.abc import Callable

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.server_url import GHIDRA_URL_SCHEME, ServerProgram, parse_server_url

log = logging.getLogger(__name__)

_PROJECT_SUBDIR = "ghidra_projects"
_PROJECT_EXT = ".gpr"


DECOMPILER_MAX_PAYLOAD_MB = 100


class _SharedDecompiler:
    """The shared DecompInterface, with per-call open/dispose made harmless."""

    def __init__(self, iface) -> None:
        self._iface = iface

    def openProgram(self, program) -> bool:
        return True

    def dispose(self) -> None:
        pass

    def close(self) -> None:
        self._iface.dispose()

    def __getattr__(self, name: str):
        return getattr(self._iface, name)


class Session:
    """Singleton managing the Ghidra program session."""

    def __init__(self):
        self._program = None
        self._program_path = ""
        self._decompiler = None
        self._consumer = None
        self._project = None
        self._project_location = None
        self._current_path: str | None = None
        self._flat_api = None
        self._attached: dict[str, Callable[[], None]] = {}
        self.capabilities: dict[str, bool] = {}

    def is_open(self) -> bool:
        return self._current_path is not None and self._program is not None

    @property
    def current_path(self) -> str | None:
        return self._current_path

    @property
    def program(self):
        return self._program

    @property
    def flat_api(self):
        return self._flat_api

    def open(
        self,
        file_path: str,
        run_auto_analysis: bool = False,
        force_new: bool = False,
        language: str = "",
        compiler_spec: str = "",
        program: str = "",
    ) -> dict:
        """Open a binary, or a program inside an existing Ghidra project.

        *file_path* is either a raw binary (imported into
        ``<dir>/ghidra_projects/<name>``) or a ``.gpr`` project file, in which
        case *program* names the program's path inside the project.

        Programs are opened through the project API (``consume_program``),
        never through ``GhidraProject``: ``GhidraProject`` keeps a "Batch
        Processing" transaction open on every program it opens, which defers
        aborts, blocks undo, and makes save fail with "Unable to lock due to
        active transaction".

        Returns a status dict on success.  Raises :class:`GhidraError` on failure.
        """
        from ghidra.program.flatapi import FlatProgramAPI  # noqa: PLC0415
        from ghidra.util.task import TaskMonitor  # noqa: PLC0415

        is_url = file_path.startswith(GHIDRA_URL_SCHEME)
        path = file_path if is_url else os.path.realpath(os.path.expanduser(file_path))

        if not is_url and not os.path.isfile(path):
            raise GhidraError(f"File not found: {path}", error_type="FileNotFoundError")

        if self.is_open():
            self.close(save=True)

        warnings: list[str] = []
        project = None
        try:
            if is_url:
                project, prog, consumer = self._open_from_server(parse_server_url(path))
            elif path.endswith(_PROJECT_EXT):
                project, prog, consumer = self._open_in_project(path, program)
            else:
                if program:
                    raise GhidraError(
                        "program is only valid with a .gpr project file_path",
                        error_type="InvalidArgument",
                    )
                project, prog, consumer = self._open_binary(
                    path, force_new, language, compiler_spec
                )

            if run_auto_analysis:
                analyze(prog)

        except GhidraError:
            if project is not None:
                project.close()
            raise
        except Exception as exc:
            if project is not None:
                project.close()
            log.exception("Failed to open database: %s", path)
            raise GhidraError(f"Failed to open database: {exc}", error_type="RuntimeError") from exc

        self._program = prog
        self._program_path = str(prog.getDomainFile().getPathname())
        self._consumer = consumer
        self._project = project
        self._project_location = None if is_url else os.path.dirname(path)
        self._current_path = path
        self._flat_api = FlatProgramAPI(prog, TaskMonitor.DUMMY)
        self.capabilities = self._probe_capabilities()
        log.info("Opened database: %s (capabilities: %s)", path, self.capabilities)
        return {"status": "ok", "path": path, "warnings": warnings}

    @staticmethod
    def _open_in_project(gpr_path: str, program_path: str):
        """Open *program_path* inside the existing project *gpr_path*."""
        import pyghidra  # noqa: PLC0415

        if not program_path:
            raise GhidraError(
                "Opening a .gpr project needs program: the program's path inside the "
                "project, e.g. /firmware/app.bin. list_project_files shows them.",
                error_type="InvalidArgument",
            )
        if not program_path.startswith("/"):
            program_path = "/" + program_path

        location = os.path.dirname(gpr_path)
        name = os.path.basename(gpr_path)[: -len(_PROJECT_EXT)]
        try:
            project = pyghidra.open_project(location, name, create=False)
        except Exception as exc:
            raise GhidraError(
                f"Cannot open project {gpr_path}: {exc}. A project open in the Ghidra GUI "
                "is locked; close it there first.",
                error_type="ProjectLocked" if "lock" in str(exc).lower() else "OpenFailed",
            ) from exc

        try:
            prog, consumer = pyghidra.consume_program(project, program_path)
        except FileNotFoundError as exc:
            project.close()
            raise GhidraError(
                f"No program {program_path} in project {gpr_path}. "
                "list_project_files shows the project's programs.",
                error_type="NotFound",
            ) from exc
        except Exception:
            project.close()
            raise
        return project, prog, consumer

    @staticmethod
    def _open_from_server(target: ServerProgram):
        """Open a program from a Ghidra Server repository.

        The repository is bound to a local shared project (see
        :func:`re_mcp_ghidra.server_projects.shared_project`), which is where
        checked-out copies live.  The program opens read-only until checkout.
        """
        import pyghidra  # noqa: PLC0415

        from re_mcp_ghidra.server_projects import shared_project  # noqa: PLC0415

        project = shared_project(target)
        try:
            prog, consumer = pyghidra.consume_program(project, target.path)
        except FileNotFoundError as exc:
            project.close()
            raise GhidraError(
                f"No program {target.path} in repository {target.repository}.",
                error_type="NotFound",
            ) from exc
        except Exception:
            project.close()
            raise
        return project, prog, consumer

    def reopen(self, while_closed=None) -> None:
        """Release the current program, optionally run *while_closed*, open it again.

        A program object opened before a checkout stays read-only, and undoing
        a checkout needs the file released; re-opening picks up the file's new
        state either way.
        """
        import pyghidra  # noqa: PLC0415
        from ghidra.program.flatapi import FlatProgramAPI  # noqa: PLC0415
        from ghidra.util.task import TaskMonitor  # noqa: PLC0415

        path = self._program_path
        self._release_attached()
        self._dispose_decompiler()
        self._program.release(self._consumer)
        try:
            if while_closed is not None:
                while_closed()
        finally:
            self._program, self._consumer = pyghidra.consume_program(self._project, path)
            self._flat_api = FlatProgramAPI(self._program, TaskMonitor.DUMMY)

    def attach(self, key: str, release: Callable[[], None]) -> None:
        """Register an object that holds the program (e.g. a Version Tracking session).

        *release* runs before the program is released, on close and on reopen:
        an object still holding the program as a consumer would keep it open.
        """
        self._attached[key] = release

    def detach(self, key: str) -> None:
        """Release and forget the object registered under *key*."""
        release = self._attached.pop(key, None)
        if release is not None:
            release()

    def _release_attached(self) -> None:
        for key in list(self._attached):
            try:
                self.detach(key)
            except Exception:
                log.exception("Error releasing %s", key)

    def decompiler(self):
        """The worker's shared decompiler for the open program.

        One instance, configured from the program's own decompiler options
        (grabFromProgram), reused by every tool: starting a decompiler process
        per call made each decompile ~14x slower, and without the program's
        options some functions decompiled differently from Ghidra itself.
        decompileFunction clears the instance's cache, so it stays correct
        after edits and undo. Tools run on the main thread one at a time, so a
        single instance needs no pool. Callers' dispose()/openProgram() are
        no-ops; it is disposed when the program closes or is re-opened.
        """
        if self._decompiler is None:
            from ghidra.app.decompiler import DecompileOptions, DecompInterface  # noqa: PLC0415

            options = DecompileOptions()
            options.grabFromProgram(self._program)
            options.setMaxPayloadMBytes(DECOMPILER_MAX_PAYLOAD_MB)
            iface = DecompInterface()
            iface.setOptions(options)
            if not iface.openProgram(self._program):
                raise GhidraError(
                    f"Decompiler failed to start: {iface.getLastMessage()}",
                    error_type="DecompilationFailed",
                )
            self._decompiler = _SharedDecompiler(iface)
        return self._decompiler

    def _dispose_decompiler(self) -> None:
        if self._decompiler is not None:
            self._decompiler.close()
            self._decompiler = None

    @property
    def domain_file(self):
        """The program's file in its project.

        Not ``program.getDomainFile()``: a versioned file opened before checkout
        is an immutable copy whose domain file is a proxy that reports itself
        as unversioned.
        """
        return self._project.getProjectData().getFile(self._program_path)

    @staticmethod
    def _open_binary(path: str, force_new: bool, language: str, compiler_spec: str):
        """Import *path* into ``<dir>/ghidra_projects/<name>`` (or reopen it)."""
        import pyghidra  # noqa: PLC0415
        from java.io import File  # noqa: PLC0415

        binary_dir = os.path.dirname(path)
        binary_name = os.path.basename(path)
        project_dir = os.path.join(binary_dir, _PROJECT_SUBDIR)
        os.makedirs(project_dir, exist_ok=True)

        if force_new:
            gpr = os.path.join(project_dir, binary_name + _PROJECT_EXT)
            rep = os.path.join(project_dir, binary_name + ".rep")
            if os.path.isfile(gpr):
                os.remove(gpr)
            if os.path.isdir(rep):
                shutil.rmtree(rep)
            log.info("force_new: removed existing project files")

        project = pyghidra.open_project(project_dir, binary_name, create=True)
        try:
            program_path = "/" + binary_name
            if project.getProjectData().getFile(program_path) is None:
                loader = (
                    pyghidra.program_loader()
                    .project(project)
                    .source(File(path))
                    .projectFolderPath("/")
                    .name(binary_name)
                )
                if language:
                    _check_language(language, compiler_spec)
                    loader = loader.language(language)
                    if compiler_spec:
                        loader = loader.compiler(compiler_spec)
                try:
                    with loader.load() as results:
                        results.save(pyghidra.task_monitor())
                except GhidraError:
                    raise
                except Exception as exc:
                    raise GhidraError(
                        f"Failed to import binary: {path}: {exc}",
                        error_type="ImportFailed",
                    ) from exc
            prog, consumer = pyghidra.consume_program(project, program_path)
        except Exception:
            project.close()
            raise
        return project, prog, consumer

    def _probe_capabilities(self) -> dict[str, bool]:
        """Detect which optional features are available."""
        return {
            "decompiler": True,
        }

    def save(self, comment: str = "ghidra-mcp-next") -> None:
        """Persist the current program to its project."""
        if self._program is None or self._project is None:
            raise GhidraError("No database is open.", error_type="NoDatabase")

        from ghidra.util.task import TaskMonitor  # noqa: PLC0415

        info = self._program.getCurrentTransactionInfo()
        if info is not None:
            raise GhidraError(
                f"Cannot save while transaction {info.getDescription()!r} is open.",
                error_type="TransactionOpen",
            )

        df = self._program.getDomainFile()
        if df is None or not df.canSave():
            raise GhidraError(
                "This program cannot be saved: it is read-only, or it is a versioned "
                "file that is not checked out (checkout_file first).",
                error_type="ReadOnly",
            )
        self._program.save(comment, TaskMonitor.DUMMY)

    def close(self, save: bool = True) -> dict:
        """Close the current database.

        Raises :class:`GhidraError` on failure.
        """
        if not self.is_open():
            return {"status": "no_database_open"}

        path = self._current_path
        try:
            if save and self._program is not None and self._program.isChanged():
                self.save()
        except Exception as exc:
            log.exception("Error saving database %s", path)
            raise GhidraError(
                f"Error saving database {path}: {exc}", error_type="CloseFailed"
            ) from exc
        finally:
            try:
                self._release_attached()
                self._dispose_decompiler()
                if self._program is not None:
                    self._program.release(self._consumer)
                if self._project is not None:
                    self._project.close()
            except Exception:
                log.exception("Error releasing database %s", path)
            self._program = None
            self._consumer = None
            self._project = None
            self._project_location = None
            self._current_path = None
            self._flat_api = None

        log.info("Closed database: %s (saved=%s)", path, save)
        return {"status": "closed", "path": path, "saved": save}

    def require_open(self, fn):
        """Decorator that raises :class:`GhidraError` if no database is open."""

        def _check():
            if not self.is_open():
                raise GhidraError(
                    "No database is open. Use open_database first.",
                    error_type="NoDatabase",
                )

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args, **kwargs):
                from re_mcp_ghidra.helpers import call_ghidra  # noqa: PLC0415

                await call_ghidra(_check)
                return await fn(*args, **kwargs)

            return async_wrapper

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            _check()
            return fn(*args, **kwargs)

        return wrapper


# Module-level singleton
session = Session()


def analyze(program) -> None:
    """Run full auto-analysis on *program* inside its own transaction.

    Not ``GhidraProject.analyze``: it opens no transaction and relied on the
    one ``GhidraProject`` holds open, so on a cleanly opened program every
    analyzer write fails with NoTransactionException and analysis silently
    finds a fraction of the code.
    """
    import pyghidra  # noqa: PLC0415

    pyghidra.analyze(program)


def _check_language(language: str, compiler_spec: str) -> None:
    """Raise InvalidArgument for an unknown language or compiler spec."""
    from ghidra.program.model.lang import CompilerSpecID, LanguageID  # noqa: PLC0415

    try:
        lang = _get_language_service().getLanguage(LanguageID(language))
    except Exception as e:
        raise GhidraError(
            f"Unknown language: {language!r}. Use list_targets to see available languages.",
            error_type="InvalidArgument",
        ) from e
    if compiler_spec:
        try:
            lang.getCompilerSpecByID(CompilerSpecID(compiler_spec))
        except Exception as e:
            raise GhidraError(
                f"Unknown compiler spec: {compiler_spec!r} for language {language!r}",
                error_type="InvalidArgument",
            ) from e


def _get_language_service():
    """Get Ghidra's default language service."""

    try:
        from ghidra.app.plugin.core.analysis import AutoAnalysisManager  # noqa: PLC0415

        return AutoAnalysisManager.getLanguageService()
    except Exception:
        from ghidra.program.util import DefaultLanguageService  # noqa: PLC0415

        return DefaultLanguageService.getLanguageService()


def _terminate_handler(signum, frame):
    """SIGTERM — shut down immediately."""
    raise SystemExit(0)


# SIGTERM — hard shutdown
if hasattr(signal, "SIGTERM"):
    signal.signal(signal.SIGTERM, _terminate_handler)
